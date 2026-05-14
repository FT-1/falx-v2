// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: IPC subsystem wrapper (control-plane/internal/ipc/subsys.go).
//              Adapts the IPC server to the subsys.Subsystem interface so
//              the lifecycle manager can start/stop it with the other subsystems.
//              Also provides the MetaForwarder that reads parsed PacketMeta
//              from the AF_XDP bridge and forwards them to the AI engine as
//              InferRequest batches.
// =============================================================================

package ipc

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/ft-1/falx-v2/control-plane/internal/afxdp"
	"github.com/ft-1/falx-v2/control-plane/pkg/bpfmaps"
)

// ─── IPC Subsystem ────────────────────────────────────────────────────────────
type IPCSubsys struct {
	srv    *Server
	cancel context.CancelFunc
	log    *zap.Logger
}

func NewIPCSubsys(srv *Server, log *zap.Logger) *IPCSubsys {
	return &IPCSubsys{srv: srv, log: log}
}

func (s *IPCSubsys) Name() string { return "ipc-server" }

func (s *IPCSubsys) Start(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	go func() {
		if err := s.srv.Run(childCtx); err != nil {
			s.log.Error("IPC server exited", zap.Error(err))
		}
	}()
	return nil
}

func (s *IPCSubsys) Stop(_ context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}

func (s *IPCSubsys) HealthCheck() error { return nil }

// ─── Meta Forwarder ───────────────────────────────────────────────────────────
// MetaForwarder reads PacketMeta from the AF_XDP bridge and batches them
// into InferRequest messages sent to the AI engine via the IPC server.
type MetaForwarder struct {
	metaCh    <-chan *afxdp.PacketMeta
	srv       *Server
	batchSize int
	maxWait   time.Duration
	log       *zap.Logger

	// Stats
	forwarded  atomic.Uint64
	batches    atomic.Uint64
	dropped    atomic.Uint64
	seqCounter atomic.Uint64
}

func NewMetaForwarder(
	metaCh    <-chan *afxdp.PacketMeta,
	srv       *Server,
	batchSize int,
	log       *zap.Logger,
) *MetaForwarder {
	if batchSize <= 0 {
		batchSize = 64
	}
	return &MetaForwarder{
		metaCh:    metaCh,
		srv:       srv,
		batchSize: batchSize,
		maxWait:   10 * time.Millisecond, // Max wait before flushing a partial batch
		log:       log,
	}
}

// Run reads PacketMeta and forwards to the AI engine as InferRequest batches.
func (f *MetaForwarder) Run(ctx context.Context) {
	f.log.Info("MetaForwarder started",
		zap.Int("batch_size", f.batchSize),
		zap.Duration("max_wait", f.maxWait),
	)

	batch   := make([]PacketMeta, 0, f.batchSize)
	ticker  := time.NewTicker(f.maxWait)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		reqID := f.seqCounter.Add(1)
		req   := &InferRequest{
			RequestID: reqID,
			Packets:   batch,
		}
		select {
		case f.srv.InferRequestCh <- req:
			f.forwarded.Add(uint64(len(batch)))
			f.batches.Add(1)
		default:
			f.dropped.Add(uint64(len(batch)))
			f.log.Warn("InferRequestCh full — batch dropped",
				zap.Int("size", len(batch)))
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			f.log.Info("MetaForwarder stopped")
			return

		case meta, ok := <-f.metaCh:
			if !ok {
				flush()
				return
			}

			pm := metaToIPC(meta)
			batch = append(batch, pm)

			if len(batch) >= f.batchSize {
				flush()
			}

		case <-ticker.C:
			flush() // Flush partial batch on timeout
		}
	}
}

// ─── PacketMeta Converter ─────────────────────────────────────────────────────
func metaToIPC(m *afxdp.PacketMeta) PacketMeta {
	pm := PacketMeta{
		Protocol:      m.Protocol,
		SrcPort:       m.SrcPort,
		DstPort:       m.DstPort,
		TCPFlags:      m.TCPFlags,
		PktLen:        m.PktLen,
		FlowID:        m.FlowID,
		IsIPv6:        m.IsIPv6,
		PayloadSample: m.PayloadSample,
	}
	if m.SrcIP != nil {
		pm.SrcIP = m.SrcIP.String()
	}
	if m.DstIP != nil {
		pm.DstIP = m.DstIP.String()
	}
	return pm
}

// ─── Stats ────────────────────────────────────────────────────────────────────
type ForwarderStats struct {
	Forwarded uint64
	Batches   uint64
	Dropped   uint64
}

func (f *MetaForwarder) Stats() ForwarderStats {
	return ForwarderStats{
		Forwarded: f.forwarded.Load(),
		Batches:   f.batches.Load(),
		Dropped:   f.dropped.Load(),
	}
}
