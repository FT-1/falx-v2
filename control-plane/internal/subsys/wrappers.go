// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Subsystem adapters (control-plane/internal/subsys/wrappers.go).
//              Wraps each FALX subsystem to the Subsystem interface.
//              Each wrapper stores its own cancel function for isolated teardown.
// =============================================================================

package subsys

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/ft-1/falx-v2/control-plane/internal/afxdp"
	"github.com/ft-1/falx-v2/control-plane/pkg/bpfmaps"
	"github.com/ft-1/falx-v2/control-plane/internal/failsafe"
	"github.com/ft-1/falx-v2/control-plane/internal/honeypot"
	"github.com/ft-1/falx-v2/control-plane/internal/metrics"
)

// ─── BPF Map Manager ──────────────────────────────────────────────────────────
type BPFMapsSubsys struct {
	mgr    *bpfmaps.Manager
	expiry *bpfmaps.ExpiryDaemon
	cancel context.CancelFunc
	log    *zap.Logger
}

func NewBPFMapsSubsys(mgr *bpfmaps.Manager, log *zap.Logger) *BPFMapsSubsys {
	return &BPFMapsSubsys{
		mgr:    mgr,
		expiry: bpfmaps.NewExpiryDaemon(mgr, 60*time.Second, log),
		log:    log,
	}
}
func (s *BPFMapsSubsys) Name() string { return "bpf-maps" }
func (s *BPFMapsSubsys) Start(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	go s.expiry.Run(childCtx)
	s.log.Info("BPF Map Manager ready")
	return nil
}
func (s *BPFMapsSubsys) Stop(_ context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	return s.mgr.Close()
}
func (s *BPFMapsSubsys) HealthCheck() error {
	if _, err := s.mgr.ReadStats(); err != nil {
		return fmt.Errorf("XDP_STATS unreadable: %w", err)
	}
	return nil
}

// ─── AF_XDP Bridge ────────────────────────────────────────────────────────────
type AFXDPSubsys struct {
	bridge *afxdp.IntegratedBridge
	cancel context.CancelFunc
	log    *zap.Logger
}

func NewAFXDPSubsys(bridge *afxdp.IntegratedBridge, log *zap.Logger) *AFXDPSubsys {
	return &AFXDPSubsys{bridge: bridge, log: log}
}
func (s *AFXDPSubsys) Name() string { return "afxdp-bridge" }
func (s *AFXDPSubsys) Start(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	go func() {
		if err := s.bridge.Run(childCtx); err != nil {
			s.log.Error("AF_XDP bridge exited", zap.Error(err))
		}
	}()
	return nil
}
func (s *AFXDPSubsys) Stop(_ context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	return s.bridge.Close()
}
func (s *AFXDPSubsys) HealthCheck() error {
	if snap := s.bridge.Snapshot(); snap.FreeFrames == 0 {
		return fmt.Errorf("UMEM exhausted")
	}
	return nil
}

// ─── Failsafe Engine ──────────────────────────────────────────────────────────
type FailsafeSubsys struct {
	engine *failsafe.Engine
	cancel context.CancelFunc
	log    *zap.Logger
}

func NewFailsafeSubsys(engine *failsafe.Engine, log *zap.Logger) *FailsafeSubsys {
	return &FailsafeSubsys{engine: engine, log: log}
}
func (s *FailsafeSubsys) Name() string { return "failsafe-engine" }
func (s *FailsafeSubsys) Start(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	go func() {
		if err := s.engine.Run(childCtx); err != nil {
			s.log.Error("Failsafe engine exited", zap.Error(err))
		}
	}()
	return nil
}
func (s *FailsafeSubsys) Stop(_ context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}
func (s *FailsafeSubsys) HealthCheck() error { return nil }

// ─── Honeypot ─────────────────────────────────────────────────────────────────
type HoneypotSubsys struct {
	mgr     *honeypot.Manager
	tracker *honeypot.Tracker
	metaCh  <-chan *afxdp.PacketMeta
	cancel  context.CancelFunc
	log     *zap.Logger
}

func NewHoneypotSubsys(
	mgr     *honeypot.Manager,
	tracker *honeypot.Tracker,
	metaCh  <-chan *afxdp.PacketMeta,
	log     *zap.Logger,
) *HoneypotSubsys {
	return &HoneypotSubsys{mgr: mgr, tracker: tracker, metaCh: metaCh, log: log}
}
func (s *HoneypotSubsys) Name() string { return "honeypot" }
func (s *HoneypotSubsys) Start(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	go s.mgr.Run(childCtx)
	go s.tracker.Run(childCtx, s.metaCh)
	return nil
}
func (s *HoneypotSubsys) Stop(_ context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	s.mgr.Close()
	return nil
}
func (s *HoneypotSubsys) HealthCheck() error { return nil }

// ─── Metrics ──────────────────────────────────────────────────────────────────
type MetricsSubsys struct {
	collector *metrics.Collector
	server    *metrics.Server
	interval  time.Duration
	cancel    context.CancelFunc
	log       *zap.Logger
}

func NewMetricsSubsys(
	collector *metrics.Collector,
	server    *metrics.Server,
	interval  time.Duration,
	log       *zap.Logger,
) *MetricsSubsys {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &MetricsSubsys{
		collector: collector,
		server:    server,
		interval:  interval,
		log:       log,
	}
}
func (s *MetricsSubsys) Name() string { return "metrics" }
func (s *MetricsSubsys) Start(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	go s.collector.Run(childCtx, s.interval)
	go func() {
		if err := s.server.Run(childCtx); err != nil {
			s.log.Error("Metrics server exited", zap.Error(err))
		}
	}()
	return nil
}
func (s *MetricsSubsys) Stop(_ context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}
func (s *MetricsSubsys) HealthCheck() error { return nil }
