//go:build linux
// +build linux

// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: AF_XDP socket (control-plane/internal/afxdp/socket.go).
//              Binds the AF_XDP socket to a specific NIC queue and
//              registers it in XSK_MAP so the BPF XDP program can redirect
//              packets into our UMEM.
//
//              One XDPSocket per NIC queue. For multi-queue NICs, the bridge
//              (Phase 4) creates one socket per queue.
//
//              Lifecycle:
//                NewXDPSocket() → bind to (ifindex, queue_id) → register in XSK_MAP
//                → RX loop reads packets from RX ring
//                → Processed packets returned to FILL ring (or TX'd back)
//                → Close() detaches from kernel
// =============================================================================

package afxdp

import (
	"fmt"
	"net"
	"unsafe"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// ─── Bind Struct (matches kernel sockaddr_xdp) ────────────────────────────────
type sockaddrXDP struct {
	Family   uint16
	Flags    uint16
	Ifindex  uint32
	QueueID  uint32
	SharedUMEMFD uint32
}

// ─── XDP Bind Flags ───────────────────────────────────────────────────────────
const (
	XDP_SHARED_UMEM     = 1 << 0
	XDP_COPY            = 1 << 1 // Force copy mode (for drivers without zero-copy)
	XDP_ZEROCOPY        = 1 << 2 // Force zero-copy (fail if unsupported)
	XDP_USE_NEED_WAKEUP = 1 << 3 // Enable NEED_WAKEUP flag for power efficiency
)

// ─── XDPSocket ────────────────────────────────────────────────────────────────
type XDPSocket struct {
	fd      int
	ifName  string
	queueID uint32

	// The four rings (mmap'd, shared with kernel)
	rxRing   *Ring
	txRing   *Ring
	fillRing *Ring
	compRing *Ring

	umem *UMEM
	log  *zap.Logger
}

// ─── Constructor ──────────────────────────────────────────────────────────────
func NewXDPSocket(
	umem    *UMEM,
	ifName  string,
	queueID uint32,
	copyMode bool, // true = SKB/copy mode for drivers without zero-copy support
	log     *zap.Logger,
) (*XDPSocket, error) {

	// Create AF_XDP socket (SOCK_RAW, not SOCK_DGRAM — we get raw frames)
	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("AF_XDP socket(): %w", err)
	}

	xsk := &XDPSocket{
		fd:      fd,
		ifName:  ifName,
		queueID: queueID,
		umem:    umem,
		log:     log,
	}

	// ── Configure FILL ring ────────────────────────────────────────────────
	fillRing, err := setupRing(umem.Fd(), XDP_UMEM_FILL_RING,
		XDP_UMEM_PGOFF_FILL_RING, FillRingSize, "fill")
	if err != nil {
		xsk.close()
		return nil, fmt.Errorf("fill ring setup: %w", err)
	}
	xsk.fillRing = fillRing

	// ── Configure COMPLETION ring ──────────────────────────────────────────
	compRing, err := setupRing(umem.Fd(), XDP_UMEM_COMPLETION_RING,
		XDP_UMEM_PGOFF_COMP_RING, CompletionRingSize, "completion")
	if err != nil {
		xsk.close()
		return nil, fmt.Errorf("completion ring setup: %w", err)
	}
	xsk.compRing = compRing

	// ── Configure RX ring ──────────────────────────────────────────────────
	rxRing, err := setupRing(fd, XDP_RX_RING,
		XDP_PGOFF_RX_RING, RxRingSize, "rx")
	if err != nil {
		xsk.close()
		return nil, fmt.Errorf("rx ring setup: %w", err)
	}
	xsk.rxRing = rxRing

	// ── Configure TX ring ──────────────────────────────────────────────────
	txRing, err := setupRing(fd, XDP_TX_RING,
		XDP_PGOFF_TX_RING, TxRingSize, "tx")
	if err != nil {
		xsk.close()
		return nil, fmt.Errorf("tx ring setup: %w", err)
	}
	xsk.txRing = txRing

	// ── Bind socket to NIC queue ───────────────────────────────────────────
	if err := xsk.bind(ifName, queueID, copyMode); err != nil {
		xsk.close()
		return nil, fmt.Errorf("bind: %w", err)
	}

	// ── Pre-populate FILL ring with all available frames ──────────────────
	// This gives the kernel empty buffers to write incoming packets into.
	if err := xsk.prefillFillRing(); err != nil {
		xsk.close()
		return nil, fmt.Errorf("prefill fill ring: %w", err)
	}

	log.Info("AF_XDP socket created",
		zap.String("iface", ifName),
		zap.Uint32("queue_id", queueID),
		zap.Bool("copy_mode", copyMode),
		zap.Int("fd", fd),
	)
	return xsk, nil
}

// ─── Bind ─────────────────────────────────────────────────────────────────────
func (xsk *XDPSocket) bind(ifName string, queueID uint32, copyMode bool) error {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return fmt.Errorf("interface %q not found: %w", ifName, err)
	}

	flags := uint16(XDP_USE_NEED_WAKEUP)
	if copyMode {
		flags |= XDP_COPY
	} else {
		flags |= XDP_ZEROCOPY
	}

	sa := sockaddrXDP{
		Family:  unix.AF_XDP,
		Flags:   flags,
		Ifindex: uint32(iface.Index),
		QueueID: queueID,
	}

	_, _, errno := unix.RawSyscall(
		unix.SYS_BIND,
		uintptr(xsk.fd),
		uintptr(unsafe.Pointer(&sa)),
		unsafe.Sizeof(sa),
	)
	if errno != 0 {
		return fmt.Errorf("bind(%s, queue=%d): %w", ifName, queueID, errno)
	}
	return nil
}

// ─── Fill Ring Pre-population ─────────────────────────────────────────────────
// Pre-populate the FILL ring with all available UMEM frames so the NIC
// has buffers ready to receive packets from the first moment.
func (xsk *XDPSocket) prefillFillRing() error {
	batchSize := uint32(FillRingSize)
	frames    := make([]uint64, batchSize)
	filled    := uint32(0)

	for filled < batchSize {
		frame, ok := xsk.umem.AllocFrame()
		if !ok {
			break
		}
		frames[filled] = frame
		filled++
	}

	if filled == 0 {
		return fmt.Errorf("no UMEM frames available for FILL ring pre-population")
	}

	produced := xsk.fillRing.FillProduce(frames[:filled])
	xsk.log.Debug("FILL ring pre-populated",
		zap.Uint32("frames_added", produced),
		zap.Int("umem_remaining", xsk.umem.AvailableFrames()),
	)
	return nil
}

// ─── Socket FD (for XSK_MAP registration) ────────────────────────────────────
func (xsk *XDPSocket) Fd() int      { return xsk.fd }
func (xsk *XDPSocket) QueueID() uint32 { return xsk.queueID }

// ─── Ring Accessors (for Bridge) ──────────────────────────────────────────────
func (xsk *XDPSocket) RxRing()   *Ring { return xsk.rxRing }
func (xsk *XDPSocket) TxRing()   *Ring { return xsk.txRing }
func (xsk *XDPSocket) FillRing() *Ring { return xsk.fillRing }
func (xsk *XDPSocket) CompRing() *Ring { return xsk.compRing }

// ─── Wakeup (required when NeedsWakeup flag is set) ──────────────────────────
// Triggers the kernel to process the TX ring via a zero-data sendmsg.
// We use SendmsgN (not Sendmsg) because Sendmsg returns only `error`,
// while SendmsgN returns `(n int, err error)`. The wakeup path sends no
// payload (n is always 0). EAGAIN / ENOBUFS are non-fatal — they mean
// the kernel is already processing and the next batch will retry.
func (xsk *XDPSocket) Wakeup() error {
	_, err := unix.SendmsgN(xsk.fd, nil, nil, nil, unix.MSG_DONTWAIT)
	if err == unix.EAGAIN || err == unix.ENOBUFS {
		return nil // Non-fatal: retry on next batch
	}
	return err
}

// ─── Close ────────────────────────────────────────────────────────────────────
func (xsk *XDPSocket) Close() error {
	return xsk.close()
}

func (xsk *XDPSocket) close() error {
	var errs []error
	for _, r := range []*Ring{xsk.rxRing, xsk.txRing, xsk.fillRing, xsk.compRing} {
		if r != nil {
			if err := r.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if xsk.fd > 0 {
		if err := unix.Close(xsk.fd); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("XDPSocket close errors: %v", errs)
	}
	return nil
}
