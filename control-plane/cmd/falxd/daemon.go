//go:build linux
// +build linux

// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: falxd daemon orchestrator (control-plane/cmd/falxd/daemon.go).
//              The central wiring point of FALX V2. Constructs, orders, and
//              runs all subsystems in a clean dependency graph:
//
//              ┌──────────────┐
//              │  BPF Loader  │  (ebpf-user, Phase 2) — loads XDP program
//              └──────┬───────┘
//                     │ pins maps to /sys/fs/bpf/falx
//                     ▼
//              ┌──────────────┐
//              │  Map Manager │  (Phase 3) — rate-limited map access + audit
//              └──────┬───────┘
//                    ╔╩══════════════════════════════╗
//                    ║                               ║
//              ┌─────▼──────┐               ┌───────▼──────┐
//              │  AF_XDP    │               │   Failsafe   │
//              │  Bridge    │  (Phase 4)    │   Engine     │  (Phase 5)
//              └─────┬──────┘               └───────┬──────┘
//                    │ MetaCh                        │ transitions
//              ┌─────▼──────┐               ┌───────▼──────┐
//              │  Honeypot  │  (Phase 6)    │  SOC Backend │  (Phase 11)
//              │  Tracker   │               │  (stub)      │
//              └────────────┘               └──────────────┘
//                    ╚══════════════════════════════╣
//                                                   ║
//                                           ┌───────▼──────┐
//                                           │   Metrics    │
//                                           │   Server     │
//                                           └──────────────┘
//
//              Graceful shutdown: reverse order with 30s deadline.
//              SIGHUP: hot-reload thresholds from config (no restart needed).
// =============================================================================

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/ft-1/falx-v2/control-plane/internal/afxdp"
	"github.com/ft-1/falx-v2/control-plane/pkg/bpfmaps"
	"github.com/ft-1/falx-v2/control-plane/internal/failsafe"
	"github.com/ft-1/falx-v2/control-plane/internal/honeypot"
	"github.com/ft-1/falx-v2/control-plane/internal/metrics"
)

// ─── Daemon ───────────────────────────────────────────────────────────────────
type FalxDaemon struct {
	cfg  *FalxConfig
	log  *zap.Logger

	// rootCtx is the top-level context derived from Run's parentCtx.
	// Stored here so sub-initializers (e.g. initBPFMaps) can derive children
	// without needing context.Background() — ensuring all goroutines stop on SIGTERM.
	rootCtx context.Context

	// Subsystem handles (built during Run, used during shutdown)
	bpfMgr       *bpfmaps.Manager
	bridge        *afxdp.IntegratedBridge
	fsEngine      *failsafe.Engine
	honeypotMgr   *honeypot.Manager
	honeypotTrack *honeypot.Tracker
	metricsCol    *metrics.Collector
	metricsSrv    *metrics.Server

	// Per-subsystem cancel functions for isolated teardown
	cancelFuncs []context.CancelFunc
}

// ─── Constructor ──────────────────────────────────────────────────────────────
func NewFalxDaemon(cfg *FalxConfig, log *zap.Logger) *FalxDaemon {
	return &FalxDaemon{cfg: cfg, log: log}
}

// ─── Run ──────────────────────────────────────────────────────────────────────
func (d *FalxDaemon) Run(parentCtx context.Context) error {
	d.log.Info("=== FALX V2 IPS starting | Architect: FT-1 ===",
		zap.String("iface",    d.cfg.General.Iface),
		zap.String("xdp_mode", d.cfg.XDP.Mode),
		zap.String("pin_path", d.cfg.General.PinPath),
	)

	// Top-level context: cancelled on SIGINT/SIGTERM
	ctx, rootCancel := context.WithCancel(parentCtx)
	defer rootCancel()

	// Store root context so sub-initializers can derive from it correctly.
	d.rootCtx = ctx

	// ── [1] BPF Map Manager ───────────────────────────────────────────────
	if err := d.initBPFMaps(); err != nil {
		return fmt.Errorf("BPF map manager init: %w", err)
	}
	defer d.bpfMgr.Close()

	// ── [2] AF_XDP Bridge ─────────────────────────────────────────────────
	bridgeCtx, bridgeCancel := context.WithCancel(ctx)
	d.cancelFuncs = append(d.cancelFuncs, bridgeCancel)

	if err := d.initAFXDP(bridgeCtx); err != nil {
		return fmt.Errorf("AF_XDP bridge init: %w", err)
	}
	defer d.bridge.Close()

	// ── [3] Failsafe Engine ───────────────────────────────────────────────
	fsCtx, fsCancel := context.WithCancel(ctx)
	d.cancelFuncs = append(d.cancelFuncs, fsCancel)

	d.initFailsafe(fsCtx)

	// ── [4] Honeypot Manager + Tracker ───────────────────────────────────
	honeypotCtx, honeypotCancel := context.WithCancel(ctx)
	d.cancelFuncs = append(d.cancelFuncs, honeypotCancel)

	if err := d.initHoneypot(honeypotCtx); err != nil {
		d.log.Warn("Honeypot init failed (non-fatal, disabling honeypot)",
			zap.Error(err))
	}

	// ── [5] Metrics ───────────────────────────────────────────────────────
	metricsCtx, metricsCancel := context.WithCancel(ctx)
	d.cancelFuncs = append(d.cancelFuncs, metricsCancel)

	d.initMetrics(metricsCtx)

	d.log.Info("All FALX V2 subsystems running",
		zap.String("metrics", d.cfg.Metrics.PrometheusAddr),
		zap.String("iface",   d.cfg.General.Iface),
	)

	// ── Signal Handling ───────────────────────────────────────────────────
	return d.waitForSignals(ctx, rootCancel)
}

// ─── Signal Handler ───────────────────────────────────────────────────────────
func (d *FalxDaemon) waitForSignals(ctx context.Context, cancel context.CancelFunc) error {
	sigCh   := make(chan os.Signal, 4)
	signal.Notify(sigCh,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGHUP,
		syscall.SIGUSR1,
	)
	defer signal.Stop(sigCh)

	for {
		select {
		case <-ctx.Done():
			d.shutdown()
			return nil

		case sig := <-sigCh:
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				d.log.Warn("Shutdown signal received",
					zap.String("signal", sig.String()))
				cancel()

			case syscall.SIGHUP:
				// Hot reload: re-read config thresholds without restart
				d.log.Info("SIGHUP: reloading configuration")
				d.hotReload()

			case syscall.SIGUSR1:
				// Dump current stats to log
				d.dumpStats()
			}
		}
	}
}

// ─── Subsystem Initializers ───────────────────────────────────────────────────

func (d *FalxDaemon) initBPFMaps() error {
	rlCfg := bpfmaps.DefaultRateLimitConfig()

	mgrCfg := bpfmaps.ManagerConfig{
		PinPath:       d.cfg.General.PinPath,
		RLConfig:      rlCfg,
		AuditLogPath:  "/var/log/falx/audit.jsonl",
		SweepInterval: 60 * time.Second,
	}

	mgr, err := bpfmaps.NewManager(mgrCfg, d.log)
	if err != nil {
		return err
	}
	d.bpfMgr = mgr

	// Start TTL expiry daemon — use the root daemon context so it stops on SIGTERM.
	expiry := bpfmaps.NewExpiryDaemon(mgr, 60*time.Second, d.log)
	expiryCtx, cancel := context.WithCancel(d.rootCtx)
	d.cancelFuncs = append(d.cancelFuncs, cancel)
	go expiry.Run(expiryCtx)

	d.log.Info("BPF Map Manager ready",
		zap.String("pin_path", d.cfg.General.PinPath))
	return nil
}

func (d *FalxDaemon) initAFXDP(ctx context.Context) error {
	bridgeCfg := afxdp.BridgeConfig{
		IfName:          d.cfg.General.Iface,
		QueueID:         d.cfg.AFXDP.QueueID,
		NumFrames:       d.cfg.AFXDP.UMEMSize,
		FrameSize:       d.cfg.AFXDP.FrameSize,
		BatchSize:       d.cfg.AFXDP.BatchSize,
		CopyMode:        d.cfg.XDP.Mode == "skb",
		MetaChannelSize: 8192,
	}

	bridge, err := afxdp.NewIntegratedBridge(bridgeCfg, d.bpfMgr, d.log)
	if err != nil {
		return err
	}
	d.bridge = bridge

	go func() {
		if err := bridge.Run(ctx); err != nil {
			d.log.Error("AF_XDP bridge exited", zap.Error(err))
		}
	}()

	d.log.Info("AF_XDP zero-copy bridge running",
		zap.String("iface",    d.cfg.General.Iface),
		zap.Uint32("queue_id", d.cfg.AFXDP.QueueID),
	)
	return nil
}

func (d *FalxDaemon) initFailsafe(ctx context.Context) {
	fsCfg := failsafe.EngineConfig{
		PollInterval: 200 * time.Millisecond,
		Detector: failsafe.DetectorConfig{
			PPSThreshold:            d.cfg.Failsafe.PPSThreshold,
			BPSThreshold:            d.cfg.Failsafe.BPSThreshold,
			SpikeMultiplier:         5.0,
			BaselineWindow:          10,
			DropRatioThreshold:      0.90,
			ParseErrorRateThreshold: 0.05,
			ConsecutiveViolations:   3,
			ConsecutiveClean:        5,
		},
		Recovery: failsafe.RecoveryConfig{
			BaseCooldown:        time.Duration(d.cfg.Failsafe.CooldownSecs) * time.Second,
			MaxCooldown:         3600 * time.Second,
			BackoffResetAfter:   5 * time.Minute,
			HalfOpenProbeWindow: 5 * time.Second,
		},
	}

	d.fsEngine = failsafe.NewEngine(fsCfg, d.bpfMgr, d.log)

	go func() {
		if err := d.fsEngine.Run(ctx); err != nil {
			d.log.Error("Failsafe engine exited", zap.Error(err))
		}
	}()

	// Forward circuit breaker transitions to audit log.
	// Uses select with ctx.Done() so the goroutine exits cleanly when the
	// failsafe context is cancelled — avoids goroutine leak if the channel
	// is never closed (e.g. engine exits via error before draining).
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case t, ok := <-d.fsEngine.Transitions:
				if !ok {
					return
				}
				d.log.Warn("Circuit breaker transition",
					zap.String("from",   t.From.String()),
					zap.String("to",     t.To.String()),
					zap.String("reason", t.Reason),
					zap.Uint64("pps",    t.CurrentPPS),
					zap.Int("trips",     t.TripCount),
				)
			}
		}
	}()

	d.log.Info("Failsafe engine running",
		zap.Uint64("pps_threshold", d.cfg.Failsafe.PPSThreshold),
		zap.Uint64("bps_threshold", d.cfg.Failsafe.BPSThreshold),
	)
}

func (d *FalxDaemon) initHoneypot(ctx context.Context) error {
	hpCfg := honeypot.DefaultManagerConfig(d.cfg.General.PinPath)
	hpMgr, err := honeypot.NewManager(hpCfg, d.bpfMgr, d.log)
	if err != nil {
		return err
	}
	d.honeypotMgr = hpMgr

	d.honeypotTrack = honeypot.NewTracker(d.bpfMgr, d.log)

	go hpMgr.Run(ctx)
	go d.honeypotTrack.Run(ctx, d.bridge.MetaChan())

	d.log.Info("Honeypot subsystem running")
	return nil
}

func (d *FalxDaemon) initMetrics(ctx context.Context) {
	d.metricsCol = metrics.NewCollector(d.bpfMgr, d.fsEngine, d.log)

	// Wire AF_XDP bridge snapshot
	d.metricsCol.SetAFXDPSnapshotFn(func() metrics.AFXDPSnapshot {
		s := d.bridge.Snapshot()
		return metrics.AFXDPSnapshot{
			RxPackets:     s.RxPackets,
			RxBytes:       s.RxBytes,
			ParseErrors:   s.ParseErrors,
			UMEMExhausted: s.UMEMExhausted,
			MetaChLen:     s.MetaChLen,
		}
	})

	// Wire honeypot session count
	if d.honeypotTrack != nil {
		d.metricsCol.SetHoneypotSessionFn(d.honeypotTrack.ActiveSessionCount)
	}

	go d.metricsCol.Run(ctx, 5*time.Second)

	// Metrics HTTP server
	d.metricsSrv = metrics.NewServer(d.cfg.Metrics.PrometheusAddr, d.log)

	// Register health checks
	d.metricsSrv.RegisterHealthCheck("bpf_maps", func() error {
		_, err := d.bpfMgr.ReadStats()
		return err
	})
	d.metricsSrv.RegisterHealthCheck("failsafe", func() error {
		_, err := d.bpfMgr.ReadFailsafeState()
		return err
	})

	go func() {
		if err := d.metricsSrv.Run(ctx); err != nil {
			d.log.Error("Metrics server error", zap.Error(err))
		}
	}()

	d.log.Info("Metrics server started",
		zap.String("addr", d.cfg.Metrics.PrometheusAddr))
}

// ─── Hot Reload ───────────────────────────────────────────────────────────────
func (d *FalxDaemon) hotReload() {
	newCfg, err := LoadConfig("/etc/falx/falx.toml")
	if err != nil {
		d.log.Warn("Hot reload: config read failed", zap.Error(err))
		return
	}

	// Update failsafe thresholds dynamically
	if d.fsEngine != nil {
		if err := d.fsEngine.UpdateThresholds(
			newCfg.Failsafe.PPSThreshold,
			newCfg.Failsafe.BPSThreshold,
		); err != nil {
			d.log.Error("Hot reload: threshold update failed", zap.Error(err))
		} else {
			d.log.Info("Hot reload: failsafe thresholds updated",
				zap.Uint64("pps", newCfg.Failsafe.PPSThreshold),
				zap.Uint64("bps", newCfg.Failsafe.BPSThreshold),
			)
		}
	}
}

// ─── Stats Dump (SIGUSR1) ─────────────────────────────────────────────────────
func (d *FalxDaemon) dumpStats() {
	stats, err := d.bpfMgr.ReadStats()
	if err != nil {
		d.log.Error("Stats dump failed", zap.Error(err))
		return
	}
	d.log.Info("=== FALX V2 STATS DUMP ===",
		zap.Uint64("rx_packets",    stats.RxPackets),
		zap.Uint64("rx_bytes",      stats.RxBytes),
		zap.Uint64("dropped",       stats.Dropped),
		zap.Uint64("rate_limited",  stats.RateLimited),
		zap.Uint64("passed",        stats.Passed),
		zap.Uint64("redirected",    stats.Redirected),
		zap.Uint64("failsafe_drops",stats.FailsafeDrops),
		zap.Uint64("parse_errors",  stats.ParseErrors),
	)

	if d.fsEngine != nil {
		m := d.fsEngine.Metrics()
		d.log.Info("=== FAILSAFE STATE ===",
			zap.String("state",       m.Circuit.State),
			zap.Int("trip_count",     m.Circuit.TripCount),
			zap.Duration("open_for",  m.Circuit.OpenDuration),
			zap.Uint64("total_trips", m.TotalTrips),
			zap.Float64("ema_pps",    m.Baseline.EMAPPS),
		)
	}

	if d.honeypotTrack != nil {
		d.log.Info("=== HONEYPOT STATE ===",
			zap.Int("active_sessions", d.honeypotTrack.ActiveSessionCount()),
		)
	}

	if d.bridge != nil {
		snap := d.bridge.Snapshot()
		d.log.Info("=== AF_XDP BRIDGE ===",
			zap.Uint64("rx_packets",    snap.RxPackets),
			zap.Uint64("rx_bytes",      snap.RxBytes),
			zap.Int("meta_ch_fill",     snap.MetaChLen),
			zap.Int("free_frames",      snap.FreeFrames),
		)
	}
}

// ─── Graceful Shutdown ────────────────────────────────────────────────────────
// shutdown cancels all subsystem contexts in reverse dependency order, then
// waits up to shutdownDrainTimeout for them to finish. Subsystems that embed
// their own sync.WaitGroup (e.g. AF_XDP bridge) are joined via their Close()
// deferred in Run(). The drain timer is a safety net for subsystems that only
// observe context cancellation without an exposed WaitGroup.
const shutdownDrainTimeout = 5 * time.Second

func (d *FalxDaemon) shutdown() {
	d.log.Warn("Initiating graceful shutdown...")

	// Cancel all subsystem contexts in reverse dependency order.
	for i := len(d.cancelFuncs) - 1; i >= 0; i-- {
		d.cancelFuncs[i]()
	}

	// Wait for the drain timeout. Subsystems with internal WaitGroups
	// (bridge, metrics server) will drain via their deferred Close() calls
	// in Run(). This sleep is a bounded safety net for goroutines that
	// only poll ctx.Done() on a ticker (e.g. honeypot manager, expiry daemon).
	drainTimer := time.NewTimer(shutdownDrainTimeout)
	defer drainTimer.Stop()
	<-drainTimer.C

	d.log.Info("FALX V2 shutdown complete.")
}
