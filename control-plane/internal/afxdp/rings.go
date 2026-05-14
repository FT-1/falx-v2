// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: AF_XDP ring buffer management (control-plane/internal/afxdp/rings.go).
//              Implements the four lock-free rings that form the AF_XDP
//              zero-copy datapath:
//
//              FILL ring:       User → Kernel  (give empty frames to NIC RX)
//              COMPLETION ring: Kernel → User  (NIC TX complete, reclaim frame)
//              RX ring:         Kernel → User  (received packets, with data)
//              TX ring:         User → Kernel  (transmit request)
//
//              All rings are single-producer / single-consumer (SPSC).
//              Shared between kernel and user-space via mmap.
//              Coordination via producer/consumer index counters with memory
//              barriers — no locks, no syscalls on the hot path.
// =============================================================================

package afxdp

import (
	"fmt"
	"runtime"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ─── Ring ─────────────────────────────────────────────────────────────────────
// Ring wraps a kernel-shared ring buffer.
// All pointer arithmetic uses the mmap'd base addresses.
type Ring struct {
	// Shared with kernel (via mmap) — use atomic ops to access
	producer *uint32 // kernel writes here (for RX/COMPLETION); we write for FILL/TX
	consumer *uint32 // we write here (for RX/COMPLETION); kernel writes for FILL/TX
	flags    *uint32 // XDP_RING_NEED_WAKEUP flag

	// Descriptor array base (xdpDesc for RX/TX, uint64 for FILL/COMPLETION)
	descBase unsafe.Pointer

	// Ring capacity (must be power of 2 for cheap modulo via &mask)
	size uint32
	mask uint32

	// Cached local copies to avoid atomic reads on every operation
	cachedProd uint32
	cachedCons uint32

	// Backing mmap region (kept for Munmap on close)
	mmap []byte

	name string
}

// ─── Ring Setup ───────────────────────────────────────────────────────────────
func setupRing(
	sockFd     int,
	ringType   int,   // SOL_XDP optname for ring size
	mmapOffset int64, // XDP_PGOFF_* constant
	ringSize   uint32,
	name       string,
) (*Ring, error) {
	// Tell kernel the ring size
	if err := setsockoptBytes(sockFd, SOL_XDP, ringType,
		(*[4]byte)(unsafe.Pointer(&ringSize))[:],
	); err != nil {
		return nil, fmt.Errorf("setsockopt %s size failed: %w", name, err)
	}

	// Get mmap offsets from kernel
	offsets, err := getMmapOffsets(sockFd)
	if err != nil {
		return nil, fmt.Errorf("get mmap offsets failed: %w", err)
	}

	// Select the correct sub-offset based on ring type
	var ringOff xdpRingOffset
	switch ringType {
	case XDP_RX_RING:
		ringOff = offsets.Rx
	case XDP_TX_RING:
		ringOff = offsets.Tx
	case XDP_UMEM_FILL_RING:
		ringOff = offsets.Fr
	case XDP_UMEM_COMPLETION_RING:
		ringOff = offsets.Cr
	default:
		return nil, fmt.Errorf("unknown ring type %d", ringType)
	}

	// mmap the ring into user-space
	// Size = max offset across all fields + element size * ring_size
	elemSize := uint64(unsafe.Sizeof(xdpDesc{}))
	if ringType == XDP_UMEM_FILL_RING || ringType == XDP_UMEM_COMPLETION_RING {
		elemSize = 8 // uint64 descriptor
	}
	mapSize := ringOff.Desc + elemSize*uint64(ringSize)

	mem, err := unix.Mmap(
		sockFd,
		mmapOffset,
		int(mapSize),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED|unix.MAP_POPULATE,
	)
	if err != nil {
		return nil, fmt.Errorf("mmap %s ring failed: %w", name, err)
	}

	base := unsafe.Pointer(&mem[0])

	return &Ring{
		producer: (*uint32)(unsafe.Pointer(uintptr(base) + uintptr(ringOff.Producer))),
		consumer: (*uint32)(unsafe.Pointer(uintptr(base) + uintptr(ringOff.Consumer))),
		flags:    (*uint32)(unsafe.Pointer(uintptr(base) + uintptr(ringOff.Flags))),
		descBase: unsafe.Pointer(uintptr(base) + uintptr(ringOff.Desc)),
		size:     ringSize,
		mask:     ringSize - 1,
		mmap:     mem,
		name:     name,
	}, nil
}

// ─── FILL Ring Operations ─────────────────────────────────────────────────────
// Fill ring: we produce (give empty frames to kernel for RX).

// FillProduce adds n empty frame descriptors to the FILL ring.
// Returns the number of descriptors actually added.
func (r *Ring) FillProduce(frames []uint64) uint32 {
	free := r.fillFreeSlots()
	n    := uint32(len(frames))
	if n > free {
		n = free
	}
	if n == 0 {
		return 0
	}

	prod := atomic.LoadUint32(r.producer)
	for i := uint32(0); i < n; i++ {
		idx := (prod + i) & r.mask
		*r.fillDescAt(idx) = frames[i]
	}
	// Release barrier: ensure desc writes are visible before producer update
	atomic.StoreUint32(r.producer, prod+n)
	return n
}

func (r *Ring) fillFreeSlots() uint32 {
	prod := atomic.LoadUint32(r.producer)
	cons := atomic.LoadUint32(r.consumer)
	return r.size - (prod - cons)
}

func (r *Ring) fillDescAt(idx uint32) *uint64 {
	return (*uint64)(unsafe.Pointer(uintptr(r.descBase) + uintptr(idx)*8))
}

// ─── COMPLETION Ring Operations ───────────────────────────────────────────────
// Completion ring: kernel produces (TX done, return frames).

// CompletionConsume reclaims completed TX frame descriptors.
func (r *Ring) CompletionConsume(out []uint64) uint32 {
	avail := r.completionAvailable()
	n     := uint32(len(out))
	if n > avail {
		n = avail
	}
	if n == 0 {
		return 0
	}

	cons := atomic.LoadUint32(r.consumer)
	for i := uint32(0); i < n; i++ {
		idx := (cons + i) & r.mask
		out[i] = *r.fillDescAt(idx) // Same uint64 layout as FILL ring
	}
	// Release barrier
	atomic.StoreUint32(r.consumer, cons+n)
	return n
}

func (r *Ring) completionAvailable() uint32 {
	prod := atomic.LoadUint32(r.producer)
	cons := atomic.LoadUint32(r.consumer)
	return prod - cons
}

// ─── RX Ring Operations ───────────────────────────────────────────────────────
// RX ring: kernel produces (packets arrived), we consume.

// RxConsume reads up to len(descs) received packet descriptors.
func (r *Ring) RxConsume(descs []xdpDesc) uint32 {
	avail := r.rxAvailable()
	n     := uint32(len(descs))
	if n > avail {
		n = avail
	}
	if n == 0 {
		return 0
	}

	cons := atomic.LoadUint32(r.consumer)
	for i := uint32(0); i < n; i++ {
		idx      := (cons + i) & r.mask
		descs[i] = *r.rxDescAt(idx)
	}
	// Acquire barrier before consuming
	atomic.StoreUint32(r.consumer, cons+n)
	return n
}

func (r *Ring) rxAvailable() uint32 {
	prod := atomic.LoadUint32(r.producer)
	cons := atomic.LoadUint32(r.consumer)
	return prod - cons
}

func (r *Ring) rxDescAt(idx uint32) *xdpDesc {
	return (*xdpDesc)(unsafe.Pointer(
		uintptr(r.descBase) + uintptr(idx)*unsafe.Sizeof(xdpDesc{}),
	))
}

// ─── TX Ring Operations ───────────────────────────────────────────────────────
// TX ring: we produce (transmit request), kernel consumes.

// TxProduce enqueues packet descriptors for transmission.
func (r *Ring) TxProduce(descs []xdpDesc) uint32 {
	free := r.txFreeSlots()
	n    := uint32(len(descs))
	if n > free {
		n = free
	}
	if n == 0 {
		return 0
	}

	prod := atomic.LoadUint32(r.producer)
	for i := uint32(0); i < n; i++ {
		idx := (prod + i) & r.mask
		*r.rxDescAt(idx) = descs[i] // Same layout as RX descriptors
	}
	atomic.StoreUint32(r.producer, prod+n)
	return n
}

func (r *Ring) txFreeSlots() uint32 {
	prod := atomic.LoadUint32(r.producer)
	cons := atomic.LoadUint32(r.consumer)
	return r.size - (prod - cons)
}

// ─── Wakeup ───────────────────────────────────────────────────────────────────
// NeedsWakeup returns true if the kernel needs a sendmsg() syscall to process
// the TX ring (XDP_NEED_WAKEUP mode).
func (r *Ring) NeedsWakeup() bool {
	return atomic.LoadUint32(r.flags)&1 != 0
}

// ─── Ring Available Descriptors ───────────────────────────────────────────────
func (r *Ring) Available() uint32 {
	prod := atomic.LoadUint32(r.producer)
	cons := atomic.LoadUint32(r.consumer)
	return prod - cons
}

// ─── Close ────────────────────────────────────────────────────────────────────
func (r *Ring) Close() error {
	if err := unix.Munmap(r.mmap); err != nil {
		return fmt.Errorf("ring %s munmap: %w", r.name, err)
	}
	return nil
}

// ─── Kernel mmap offset query ─────────────────────────────────────────────────
func getMmapOffsets(fd int) (xdpMmapOffsets, error) {
	var offsets xdpMmapOffsets
	size  := uint32(unsafe.Sizeof(offsets))
	_, _, errno := unix.RawSyscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(SOL_XDP),
		uintptr(XDP_MMAP_OFFSETS),
		uintptr(unsafe.Pointer(&offsets)),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if errno != 0 {
		return xdpMmapOffsets{}, fmt.Errorf("getsockopt XDP_MMAP_OFFSETS: %w", errno)
	}
	return offsets, nil
}

// ─── CPU Yield ────────────────────────────────────────────────────────────────
// busyPoll yields the CPU briefly without triggering a scheduler call.
// Used in the RX polling loop when ring is empty.
func busyPoll() {
	runtime.Gosched()
}
