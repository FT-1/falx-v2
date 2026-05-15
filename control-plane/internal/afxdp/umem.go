//go:build linux
// +build linux

// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: UMEM allocator (control-plane/internal/afxdp/umem.go).
//              UMEM (User MEMory) is the shared memory region that eliminates
//              packet copying between kernel and user-space.
//
//              Architecture:
//                Kernel XDP program → writes packet to UMEM frame
//                User-space (this code) → reads from UMEM frame
//                No memcpy. No DMA bounce buffer. Zero-copy.
//
//              Memory layout:
//                UMEM = [frame_0 | frame_1 | ... | frame_N]
//                Each frame = frame_size bytes (2048 or 4096, power of 2)
//                Total = num_frames × frame_size bytes (mmap'd, page-aligned)
//
//              Safety invariants:
//                - UMEM is created once and shared with kernel via setsockopt
//                - Frames are tracked by descriptor (offset into UMEM)
//                - The FILL ring feeds empty frame descriptors to the kernel
//                - The COMPLETION ring reclaims TX'd frame descriptors
//                - Frames in use by kernel must NEVER be accessed by user-space
// =============================================================================

package afxdp

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// ─── UMEM Configuration ───────────────────────────────────────────────────────
const (
	// FrameSize2K = 2048 bytes per frame (standard, matches most drivers)
	FrameSize2K = 2048
	// FrameSize4K = 4096 bytes per frame (required for jumbo frames)
	FrameSize4K = 4096

	// DefaultNumFrames = 4096 frames = 8 MB UMEM at 2K frame size
	DefaultNumFrames = 4096

	// Headroom reserved at the start of each frame for driver metadata
	// Must be >= XDP_PACKET_HEADROOM (256 bytes in most kernels)
	FrameHeadroom = 256

	// XDP UMEM setsockopt levels/optnames (from linux/if_xdp.h)
	SOL_XDP                   = 283
	XDP_UMEM_REG              = 4
	XDP_UMEM_FILL_RING        = 5
	XDP_UMEM_COMPLETION_RING  = 6
	XDP_RX_RING               = 1
	XDP_TX_RING               = 2
	XDP_STATISTICS            = 11
	XDP_OPTIONS               = 8

	// Ring sizes (must be power of 2)
	FillRingSize      = 4096
	CompletionRingSize = 4096
	RxRingSize        = 2048
	TxRingSize        = 2048

	// Offsets for mmap (from linux/if_xdp.h XDP_MMAP_OFFSETS)
	XDP_MMAP_OFFSETS = 3
	XDP_PGOFF_RX_RING         = 0
	XDP_PGOFF_TX_RING         = 0x80000000
	XDP_UMEM_PGOFF_FILL_RING  = 0x100000000
	XDP_UMEM_PGOFF_COMP_RING  = 0x180000000
)

// ─── UMEM Registration Struct (matches kernel xdp_umem_reg) ──────────────────
type xdpUmemReg struct {
	Addr      uint64 // Start of UMEM region (virtual address)
	Len       uint64 // Length in bytes
	ChunkSize uint32 // Frame size (chunk size in kernel terminology)
	Headroom  uint32 // Per-frame headroom bytes
	Flags     uint32
}

// ─── Ring Descriptor (matches kernel xdp_desc) ───────────────────────────────
// Used for RX and TX rings. Each descriptor points to one UMEM frame.
type xdpDesc struct {
	Addr    uint64 // Offset into UMEM (not virtual address)
	Len     uint32 // Length of packet data within frame
	Options uint32
}

// ─── Ring Offsets (returned by getsockopt XDP_MMAP_OFFSETS) ──────────────────
type xdpRingOffset struct {
	Producer uint64
	Consumer uint64
	Desc     uint64
	Flags    uint64
}

type xdpMmapOffsets struct {
	Rx xdpRingOffset
	Tx xdpRingOffset
	Fr xdpRingOffset // FILL ring
	Cr xdpRingOffset // COMPLETION ring
}

// ─── UMEM ─────────────────────────────────────────────────────────────────────
type UMEM struct {
	// The actual memory region (mmap'd, hugepage-aligned if possible)
	mem       []byte
	frameSize uint32
	numFrames uint32

	// Socket file descriptor used to register UMEM with kernel
	fd int

	// Frame descriptor pool (free frames available for use)
	freeFrames chan uint64

	log *zap.Logger
}

// ─── UMEM Constructor ─────────────────────────────────────────────────────────
func NewUMEM(numFrames, frameSize uint32, log *zap.Logger) (*UMEM, error) {
	if numFrames == 0 || (numFrames&(numFrames-1)) != 0 {
		return nil, fmt.Errorf("numFrames must be a power of 2, got %d", numFrames)
	}
	if frameSize != FrameSize2K && frameSize != FrameSize4K {
		return nil, fmt.Errorf("frameSize must be 2048 or 4096, got %d", frameSize)
	}

	totalSize := uintptr(numFrames) * uintptr(frameSize)

	// ── Allocate page-aligned memory via mmap ──────────────────────────────
	// MAP_ANONYMOUS | MAP_PRIVATE: no file backing, private mapping
	// MAP_POPULATE: pre-fault pages to avoid page-fault latency during packet processing
	mem, err := unix.Mmap(
		-1, 0,
		int(totalSize),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_ANONYMOUS|unix.MAP_PRIVATE|unix.MAP_POPULATE,
	)
	if err != nil {
		return nil, fmt.Errorf("UMEM mmap failed (%d bytes): %w", totalSize, err)
	}

	// ── Create raw AF_XDP socket ───────────────────────────────────────────
	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		unix.Munmap(mem)
		return nil, fmt.Errorf("AF_XDP socket creation failed: %w", err)
	}

	// ── Register UMEM with kernel ──────────────────────────────────────────
	reg := xdpUmemReg{
		Addr:      uint64(uintptr(unsafe.Pointer(&mem[0]))),
		Len:       uint64(totalSize),
		ChunkSize: frameSize,
		Headroom:  FrameHeadroom,
		Flags:     0,
	}

	if err := setsockoptBytes(fd, SOL_XDP, XDP_UMEM_REG,
		(*[unsafe.Sizeof(reg)]byte)(unsafe.Pointer(&reg))[:],
	); err != nil {
		unix.Close(fd)
		unix.Munmap(mem)
		return nil, fmt.Errorf("XDP_UMEM_REG setsockopt failed: %w", err)
	}

	// ── Pre-populate free frame pool ───────────────────────────────────────
	freeFrames := make(chan uint64, numFrames)
	for i := uint32(0); i < numFrames; i++ {
		// Each descriptor is the byte offset of the frame within UMEM
		freeFrames <- uint64(i) * uint64(frameSize)
	}

	u := &UMEM{
		mem:        mem,
		frameSize:  frameSize,
		numFrames:  numFrames,
		fd:         fd,
		freeFrames: freeFrames,
		log:        log,
	}

	log.Info("UMEM allocated",
		zap.Uint32("num_frames", numFrames),
		zap.Uint32("frame_size", frameSize),
		zap.Uint64("total_mb", uint64(totalSize)/1_000_000),
	)
	return u, nil
}

// ─── Frame Access ─────────────────────────────────────────────────────────────

// FrameAt returns a byte slice covering exactly one frame at the given UMEM offset.
// CALLER MUST ensure the frame is not currently owned by the kernel (not in FILL ring).
func (u *UMEM) FrameAt(offset uint64) []byte {
	start := offset + uint64(FrameHeadroom)
	end   := offset + uint64(u.frameSize)
	return u.mem[start:end]
}

// AllocFrame returns a free frame descriptor (UMEM offset).
// Returns (0, false) if no frames are available.
func (u *UMEM) AllocFrame() (uint64, bool) {
	select {
	case desc := <-u.freeFrames:
		return desc, true
	default:
		return 0, false
	}
}

// FreeFrame returns a frame back to the pool after use.
func (u *UMEM) FreeFrame(offset uint64) {
	select {
	case u.freeFrames <- offset:
	default:
		u.log.Error("UMEM frame pool overflow — frame lost",
			zap.Uint64("offset", offset))
	}
}

// AvailableFrames returns the count of free frames.
func (u *UMEM) AvailableFrames() int {
	return len(u.freeFrames)
}

// Fd returns the AF_XDP socket file descriptor.
func (u *UMEM) Fd() int { return u.fd }

// ─── Cleanup ──────────────────────────────────────────────────────────────────
func (u *UMEM) Close() error {
	errs := []error{}
	if err := unix.Close(u.fd); err != nil {
		errs = append(errs, fmt.Errorf("socket close: %w", err))
	}
	if err := unix.Munmap(u.mem); err != nil {
		errs = append(errs, fmt.Errorf("munmap: %w", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("UMEM close errors: %v", errs)
	}
	u.log.Info("UMEM released")
	return nil
}

// ─── Syscall Helper ───────────────────────────────────────────────────────────
func setsockoptBytes(fd, level, optname int, b []byte) error {
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(optname),
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(len(b)),
		0,
	)
	if errno != 0 {
		return os.NewSyscallError("setsockopt", errno)
	}
	return nil
}
