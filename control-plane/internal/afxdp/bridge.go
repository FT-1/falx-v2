// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: AF_XDP Zero-Copy Bridge (control-plane/internal/afxdp/bridge.go).
//              The bridge is the heart of the zero-copy datapath:
//
//              XDP Program (kernel) → [XSK_MAP redirect] → UMEM RX ring
//              Bridge reads from RX ring → Parses packet → PacketMeta channel
//              AI inference engine reads PacketMeta → verdict decision
//              Verdict → bpfmaps.Manager.BlockIPv4() → XDP drop on next packet
//              Empty UMEM frames → returned to FILL ring → kernel reuses them
//
//              No memcpy at any stage. The packet data stays in UMEM.
//              The AI engine receives only the parsed metadata (small struct),
//              NOT the raw packet bytes — this is the zero-copy contract.
//
//              Threading model:
//                One goroutine per NIC queue (rxLoop)
//                One goroutine for FILL ring replenishment
//                One goroutine for COMPLETION ring draining (TX path)
//                PacketMeta sent via buffered channel to AI engine goroutine pool
// =============================================================================

package afxdp

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// ─── Bridge Config ────────────────────────────────────────────────────────────
type BridgeConfig struct {
	IfName    string
	QueueID   uint32
	NumFrames uint32
	FrameSize uint32
	BatchSize uint32
	CopyMode  bool   // true = SKB copy mode (no zero-copy driver needed)
	// Channel buffer size for parsed packet metadata
	MetaChannelSize int
}

func DefaultBridgeConfig(ifName string) BridgeConfig {
	return BridgeConfig{
		IfName:          ifName,
		QueueID:         0,
		NumFrames:       DefaultNumFrames,
		FrameSize:       FrameSize2K,
		BatchSize:       64,
		CopyMode:        false,
		MetaChannelSize: 8192,
	}
}

// ─── Bridge Statistics ────────────────────────────────────────────────────────
type BridgeStats struct {
	RxPackets     atomic.Uint64
	RxBytes       atomic.Uint64
	ParseErrors   atomic.Uint64
	FillRefills   atomic.Uint64
	TxPackets     atomic.Uint64
	UMEMExhausted atomic.Uint64
}

// ─── Bridge ───────────────────────────────────────────────────────────────────
type Bridge struct {
	cfg    BridgeConfig
	umem   *UMEM
	xsk    *XDPSocket
	log    *zap.Logger
	stats  BridgeStats

	// PacketMeta is sent here after parsing — consumed by AI inference goroutines
	// This channel is the integration point with Phase 9 (AI engine)
	MetaCh chan *PacketMeta

	// done signals all goroutines to stop
	done chan struct{}
	wg   sync.WaitGroup
}

// ─── Constructor ──────────────────────────────────────────────────────────────
func NewBridge(cfg BridgeConfig, log *zap.Logger) (*Bridge, error) {
	// ── Allocate UMEM ─────────────────────────────────────────────────────
	umem, err := NewUMEM(cfg.NumFrames, cfg.FrameSize, log)
	if err != nil {
		return nil, fmt.Errorf("UMEM alloc: %w", err)
	}

	// ── Create AF_XDP socket ─────────────────────────────────────────────
	xsk, err := NewXDPSocket(umem, cfg.IfName, cfg.QueueID, cfg.CopyMode, log)
	if err != nil {
		umem.Close()
		return nil, fmt.Errorf("XDP socket: %w", err)
	}

	b := &Bridge{
		cfg:    cfg,
		umem:   umem,
		xsk:    xsk,
		log:    log,
		MetaCh: make(chan *PacketMeta, cfg.MetaChannelSize),
		done:   make(chan struct{}),
	}

	log.Info("AF_XDP bridge initialized",
		zap.String("iface", cfg.IfName),
		zap.Uint32("queue", cfg.QueueID),
		zap.Uint32("num_frames", cfg.NumFrames),
		zap.Uint32("frame_size", cfg.FrameSize),
		zap.Bool("copy_mode", cfg.CopyMode),
	)
	return b, nil
}

// ─── XSK File Descriptor ─────────────────────────────────────────────────────
// Called by the control plane to register this socket in XSK_MAP.
func (b *Bridge) XSKFd() int { return b.xsk.Fd() }

// ─── Run ──────────────────────────────────────────────────────────────────────
// Run starts all bridge goroutines. Blocks until ctx is cancelled.
func (b *Bridge) Run(ctx context.Context) error {
	b.log.Info("AF_XDP bridge starting RX/FILL loops")

	// ── RX loop: reads packets from RX ring, parses, sends to MetaCh ─────
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		b.rxLoop(ctx)
	}()

	// ── FILL replenishment loop ────────────────────────────────────────────
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		b.fillLoop(ctx)
	}()

	// ── COMPLETION ring drain (reclaims TX'd frames) ───────────────────────
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		b.completionLoop(ctx)
	}()

	<-ctx.Done()
	close(b.done)
	b.wg.Wait()
	b.log.Info("AF_XDP bridge stopped")
	return nil
}

// ─── RX Loop ──────────────────────────────────────────────────────────────────
// Reads packets from the RX ring in batches.
// For each packet: parse headers → send PacketMeta → schedule FILL refill.
func (b *Bridge) rxLoop(ctx context.Context) {
	rxDescs  := make([]xdpDesc, b.cfg.BatchSize)
	toRefill := make([]uint64, 0, b.cfg.BatchSize)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n := b.xsk.RxRing().RxConsume(rxDescs)
		if n == 0 {
			// Empty ring: yield CPU briefly (avoids spinning at 100%)
			busyPoll()
			continue
		}

		toRefill = toRefill[:0]

		for i := uint32(0); i < n; i++ {
			desc := rxDescs[i]

			// Get frame bytes from UMEM (zero-copy: slice into shared memory)
			frameBytes := b.umem.FrameAt(desc.Addr)
			if uint32(len(frameBytes)) < desc.Len {
				b.stats.ParseErrors.Add(1)
				toRefill = append(toRefill, desc.Addr)
				continue
			}

			pktBytes := frameBytes[:desc.Len]
			b.stats.RxPackets.Add(1)
			b.stats.RxBytes.Add(uint64(desc.Len))

			// Parse packet metadata (only header fields, no payload copy)
			meta, err := ParseFrame(pktBytes, desc.Addr)
			if err != nil {
				b.stats.ParseErrors.Add(1)
				toRefill = append(toRefill, desc.Addr)
				continue
			}

			// Send to AI inference pipeline (non-blocking)
			// If channel is full, drop the meta (not the packet — XDP already passed it)
			select {
			case b.MetaCh <- meta:
				// Frame returned to FILL ring AFTER AI engine signals it's done
				// For now: return immediately (AI works with metadata copy)
				// Phase 9 will implement proper frame lifecycle tracking
				toRefill = append(toRefill, desc.Addr)
			default:
				b.log.Warn("MetaCh full — packet meta dropped (AI engine too slow)")
				toRefill = append(toRefill, desc.Addr)
			}
		}

		// Batch-return processed frames to FILL ring
		if len(toRefill) > 0 {
			added := b.xsk.FillRing().FillProduce(toRefill)
			b.stats.FillRefills.Add(uint64(added))
			if added < uint32(len(toRefill)) {
				b.log.Warn("FILL ring full — some frames lost",
					zap.Int("lost", len(toRefill)-int(added)))
			}
		}

		// Wake up kernel if needed (XDP_USE_NEED_WAKEUP mode)
		if b.xsk.FillRing().NeedsWakeup() {
			if err := b.xsk.Wakeup(); err != nil {
				b.log.Error("XSK wakeup failed", zap.Error(err))
			}
		}
	}
}

// ─── FILL Replenishment Loop ───────────────────────────────────────────────────
// Periodically checks if FILL ring needs more frames and adds them.
// This is a safety net for the case where rxLoop can't return frames fast enough.
func (b *Bridge) fillLoop(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.replenishFillRing()
		}
	}
}

func (b *Bridge) replenishFillRing() {
	available := b.umem.AvailableFrames()
	if available == 0 {
		b.stats.UMEMExhausted.Add(1)
		b.log.Warn("UMEM frame pool exhausted — check AI engine throughput")
		return
	}

	// Add up to half of available frames to FILL ring
	toAdd := available / 2
	if toAdd == 0 {
		return
	}

	frames := make([]uint64, toAdd)
	for i := range frames {
		frame, ok := b.umem.AllocFrame()
		if !ok {
			frames = frames[:i]
			break
		}
		frames[i] = frame
	}

	if len(frames) > 0 {
		b.xsk.FillRing().FillProduce(frames)
	}
}

// ─── COMPLETION Ring Drain ────────────────────────────────────────────────────
// Reclaims UMEM frames after successful TX (used when bridge sends packets back).
func (b *Bridge) completionLoop(ctx context.Context) {
	batch := make([]uint64, b.cfg.BatchSize)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n := b.xsk.CompRing().CompletionConsume(batch)
		if n == 0 {
			busyPoll()
			continue
		}

		for i := uint32(0); i < n; i++ {
			b.umem.FreeFrame(batch[i])
		}
	}
}

// ─── Stats ────────────────────────────────────────────────────────────────────
type BridgeSnapshot struct {
	RxPackets     uint64
	RxBytes       uint64
	ParseErrors   uint64
	FillRefills   uint64
	UMEMExhausted uint64
	MetaChLen     int
	MetaChCap     int
	FreeFrames    int
}

func (b *Bridge) Snapshot() BridgeSnapshot {
	return BridgeSnapshot{
		RxPackets:     b.stats.RxPackets.Load(),
		RxBytes:       b.stats.RxBytes.Load(),
		ParseErrors:   b.stats.ParseErrors.Load(),
		FillRefills:   b.stats.FillRefills.Load(),
		UMEMExhausted: b.stats.UMEMExhausted.Load(),
		MetaChLen:     len(b.MetaCh),
		MetaChCap:     cap(b.MetaCh),
		FreeFrames:    b.umem.AvailableFrames(),
	}
}

// ─── Close ────────────────────────────────────────────────────────────────────
// Close must only be called after Run() has returned (i.e. ctx was cancelled).
// Closing MetaCh before the goroutines that write to it have exited causes a
// "send on closed channel" panic. The correct order is:
//   1. Cancel the ctx passed to Run() → goroutines observe ctx.Done() and exit.
//   2. Run() closes b.done and waits on b.wg.
//   3. Only then call Close() to release OS resources.
func (b *Bridge) Close() error {
	// Goroutines are already done by this point (Run returned). Safe to close.
	b.wg.Wait()
	close(b.MetaCh)

	var errs []error
	if err := b.xsk.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := b.umem.Close(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("bridge close: %v", errs)
	}
	b.log.Info("AF_XDP bridge closed cleanly")
	return nil
}
