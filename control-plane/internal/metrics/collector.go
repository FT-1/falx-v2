// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Prometheus metrics collector (control-plane/internal/metrics/collector.go).
//              Aggregates telemetry from all FALX subsystems into a unified
//              Prometheus metric set. Scraped by Prometheus every 15s.
//
//              Metric namespaces:
//                falx_xdp_*       — kernel-side XDP stats (from BPF PerCpuArray)
//                falx_failsafe_*  — circuit breaker state and trip counters
//                falx_maps_*      — BPF map write rate-limiter stats
//                falx_afxdp_*     — AF_XDP bridge throughput
//                falx_honeypot_*  — honeypot session counters
//                falx_system_*    — daemon uptime and health
// =============================================================================

package metrics

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/ft-1/falx-v2/control-plane/pkg/bpfmaps"
	"github.com/ft-1/falx-v2/control-plane/internal/failsafe"
)

// ─── Collector ────────────────────────────────────────────────────────────────
type Collector struct {
	log     *zap.Logger
	bpfMgr  *bpfmaps.Manager
	fsEngine *failsafe.Engine

	// Optional: AF_XDP bridge snapshot func (set after bridge init)
	afxdpSnapshotFn func() AFXDPSnapshot
	// Optional: honeypot session count func
	honeypotSessionFn func() int

	// ── XDP Gauges ───────────────────────────────────────────────────────
	xdpRxPackets    prometheus.Counter
	xdpRxBytes      prometheus.Counter
	xdpDropped      prometheus.Counter
	xdpRateLimited  prometheus.Counter
	xdpPassed       prometheus.Counter
	xdpRedirected   prometheus.Counter
	xdpFailsafe     prometheus.Counter
	xdpParseErrors  prometheus.Counter
	xdpCoolingBans  prometheus.Counter
	xdpSynFloodBans prometheus.Counter

	// ── Failsafe Gauges ───────────────────────────────────────────────────
	failsafeCircuitOpen prometheus.Gauge
	failsafeTripTotal   prometheus.Counter
	failsafeCloseTotal  prometheus.Counter
	failsafeCurrentPPS  prometheus.Gauge
	failsafeCurrentBPS  prometheus.Gauge
	failsafeEMAPPS      prometheus.Gauge

	// ── BPF Map Rate Limiter ──────────────────────────────────────────────
	mapOpsAccepted *prometheus.CounterVec
	mapOpsDropped  *prometheus.CounterVec

	// ── AF_XDP Bridge ────────────────────────────────────────────────────
	afxdpRxPackets   prometheus.Gauge
	afxdpRxBytes     prometheus.Gauge
	afxdpParseErrors prometheus.Gauge
	afxdpUMEMExhaust prometheus.Gauge
	afxdpMetaChanLen prometheus.Gauge

	// ── Honeypot ─────────────────────────────────────────────────────────
	honeypotActiveSessions prometheus.Gauge

	// ── System ───────────────────────────────────────────────────────────
	falxUptime     prometheus.Gauge
	falxBuildInfo  *prometheus.GaugeVec
	startTime      time.Time
}

// AFXDPSnapshot is passed from the bridge to avoid circular imports.
type AFXDPSnapshot struct {
	RxPackets     uint64
	RxBytes       uint64
	ParseErrors   uint64
	UMEMExhausted uint64
	MetaChLen     int
}

// ─── Constructor ──────────────────────────────────────────────────────────────
func NewCollector(
	bpfMgr   *bpfmaps.Manager,
	fsEngine *failsafe.Engine,
	log      *zap.Logger,
) *Collector {
	c := &Collector{
		log:      log,
		bpfMgr:   bpfMgr,
		fsEngine: fsEngine,
		startTime: time.Now(),
	}
	c.registerMetrics()
	return c
}

func (c *Collector) SetAFXDPSnapshotFn(fn func() AFXDPSnapshot) {
	c.afxdpSnapshotFn = fn
}

func (c *Collector) SetHoneypotSessionFn(fn func() int) {
	c.honeypotSessionFn = fn
}

// ─── Metric Registration ──────────────────────────────────────────────────────
func (c *Collector) registerMetrics() {
	// XDP
	c.xdpRxPackets    = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "falx", Subsystem: "xdp", Name: "rx_packets_total",     Help: "Total packets received by XDP"})
	c.xdpRxBytes      = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "falx", Subsystem: "xdp", Name: "rx_bytes_total",       Help: "Total bytes received by XDP"})
	c.xdpDropped      = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "falx", Subsystem: "xdp", Name: "dropped_total",        Help: "Packets dropped by blocklist"})
	c.xdpRateLimited  = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "falx", Subsystem: "xdp", Name: "rate_limited_total",   Help: "Packets dropped by rate limiter"})
	c.xdpPassed       = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "falx", Subsystem: "xdp", Name: "passed_total",         Help: "Packets passed to network stack"})
	c.xdpRedirected   = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "falx", Subsystem: "xdp", Name: "redirected_total",     Help: "Packets redirected to honeypot"})
	c.xdpFailsafe     = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "falx", Subsystem: "xdp", Name: "failsafe_drops_total", Help: "Packets dropped by circuit breaker"})
	c.xdpParseErrors  = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "falx", Subsystem: "xdp", Name: "parse_errors_total",   Help: "Malformed packet parse errors"})
	c.xdpCoolingBans  = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "falx", Subsystem: "xdp", Name: "cooling_bans_total",   Help: "Auto-bans from rate-limit cooling tracker"})
	c.xdpSynFloodBans = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "falx", Subsystem: "xdp", Name: "syn_flood_bans_total", Help: "Auto-bans from SYN flood heuristic (r≥8)"})

	// Failsafe
	c.failsafeCircuitOpen = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "falx", Subsystem: "failsafe", Name: "circuit_open",    Help: "1 = circuit OPEN (DDoS mode), 0 = CLOSED"})
	c.failsafeTripTotal   = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "falx", Subsystem: "failsafe", Name: "trips_total",  Help: "Total circuit breaker trips"})
	c.failsafeCloseTotal  = prometheus.NewCounter(prometheus.CounterOpts{Namespace: "falx", Subsystem: "failsafe", Name: "closes_total", Help: "Total circuit breaker closes"})
	c.failsafeCurrentPPS  = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "falx", Subsystem: "failsafe", Name: "current_pps",     Help: "Current rolling packets/sec"})
	c.failsafeCurrentBPS  = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "falx", Subsystem: "failsafe", Name: "current_bps",     Help: "Current rolling bits/sec"})
	c.failsafeEMAPPS      = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "falx", Subsystem: "failsafe", Name: "ema_pps_baseline", Help: "EMA baseline PPS for spike detection"})

	// BPF Map rate limiter
	c.mapOpsAccepted = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "falx", Subsystem: "maps", Name: "ops_accepted_total", Help: "BPF map write ops accepted"}, []string{"op"})
	c.mapOpsDropped  = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "falx", Subsystem: "maps", Name: "ops_dropped_total",  Help: "BPF map write ops rate-limited"}, []string{"op"})

	// AF_XDP
	c.afxdpRxPackets   = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "falx", Subsystem: "afxdp", Name: "rx_packets",       Help: "AF_XDP RX packet count"})
	c.afxdpRxBytes     = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "falx", Subsystem: "afxdp", Name: "rx_bytes",         Help: "AF_XDP RX byte count"})
	c.afxdpParseErrors = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "falx", Subsystem: "afxdp", Name: "parse_errors",     Help: "AF_XDP user-space parse errors"})
	c.afxdpUMEMExhaust = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "falx", Subsystem: "afxdp", Name: "umem_exhausted",   Help: "UMEM frame pool exhaustion events"})
	c.afxdpMetaChanLen = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "falx", Subsystem: "afxdp", Name: "meta_chan_len",    Help: "AF_XDP→AI metadata channel fill level"})

	// Honeypot
	c.honeypotActiveSessions = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "falx", Subsystem: "honeypot", Name: "active_sessions", Help: "Active honeypot sessions"})

	// System
	c.falxUptime    = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "falx", Subsystem: "system", Name: "uptime_seconds",   Help: "Daemon uptime in seconds"})
	c.falxBuildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: "falx", Subsystem: "system", Name: "build_info",    Help: "Build metadata"}, []string{"version", "architect"})

	// Register all
	collectors := []prometheus.Collector{
		c.xdpRxPackets, c.xdpRxBytes, c.xdpDropped, c.xdpRateLimited,
		c.xdpPassed, c.xdpRedirected, c.xdpFailsafe, c.xdpParseErrors,
		c.xdpCoolingBans, c.xdpSynFloodBans,
		c.failsafeCircuitOpen, c.failsafeTripTotal, c.failsafeCloseTotal,
		c.failsafeCurrentPPS, c.failsafeCurrentBPS, c.failsafeEMAPPS,
		c.mapOpsAccepted, c.mapOpsDropped,
		c.afxdpRxPackets, c.afxdpRxBytes, c.afxdpParseErrors,
		c.afxdpUMEMExhaust, c.afxdpMetaChanLen,
		c.honeypotActiveSessions,
		c.falxUptime, c.falxBuildInfo,
	}
	for _, col := range collectors {
		prometheus.MustRegister(col)
	}

	c.falxBuildInfo.WithLabelValues("0.1.0", "FT-1").Set(1)
}

// ─── Collection Loop ──────────────────────────────────────────────────────────
// Run polls all subsystems and updates Prometheus gauges.
// Prometheus counters are updated with deltas (last - previous).
func (c *Collector) Run(ctx context.Context, interval time.Duration) {
	c.log.Info("Metrics collector started", zap.Duration("interval", interval))
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var prevStats bpfmaps.XdpStats

	for {
		select {
		case <-ctx.Done():
			c.log.Info("Metrics collector stopped")
			return
		case <-ticker.C:
			c.collect(&prevStats)
		}
	}
}

func (c *Collector) collect(prev *bpfmaps.XdpStats) {
	// ── XDP Stats ─────────────────────────────────────────────────────────
	stats, err := c.bpfMgr.ReadStats()
	if err != nil {
		c.log.Error("Metrics: failed to read XDP stats", zap.Error(err))
	} else {
		// Counters: add delta since last collection
		addCounter(c.xdpRxPackets,    stats.RxPackets     - prev.RxPackets)
		addCounter(c.xdpRxBytes,      stats.RxBytes       - prev.RxBytes)
		addCounter(c.xdpDropped,      stats.Dropped       - prev.Dropped)
		addCounter(c.xdpRateLimited,  stats.RateLimited   - prev.RateLimited)
		addCounter(c.xdpPassed,       stats.Passed        - prev.Passed)
		addCounter(c.xdpRedirected,   stats.Redirected    - prev.Redirected)
		addCounter(c.xdpFailsafe,     stats.FailsafeDrops - prev.FailsafeDrops)
		addCounter(c.xdpParseErrors,  stats.ParseErrors   - prev.ParseErrors)
		addCounter(c.xdpCoolingBans,  stats.CoolingBans   - prev.CoolingBans)
		addCounter(c.xdpSynFloodBans, stats.SynFloodBans  - prev.SynFloodBans)
		*prev = stats
	}

	// ── Failsafe ──────────────────────────────────────────────────────────
	if c.fsEngine != nil {
		m := c.fsEngine.Metrics()
		snap := m.Circuit
		baseline := m.Baseline

		open := float64(0)
		if snap.State == "OPEN" || snap.State == "HALF_OPEN" {
			open = 1
		}
		c.failsafeCircuitOpen.Set(open)
		c.failsafeEMAPPS.Set(baseline.EMAPPS)

		// Failsafe state from BPF map
		if fsState, err := c.bpfMgr.ReadFailsafeState(); err == nil {
			c.failsafeCurrentPPS.Set(float64(fsState.CurrentPPS))
			c.failsafeCurrentBPS.Set(float64(fsState.CurrentBPS))
		}
	}

	// ── BPF Map Rate Limiter ──────────────────────────────────────────────
	for op, counts := range c.bpfMgr.RateLimiterStats() {
		c.mapOpsAccepted.WithLabelValues(op).Add(float64(counts["accepted"]))
		c.mapOpsDropped.WithLabelValues(op).Add(float64(counts["dropped"]))
	}

	// ── AF_XDP Bridge ─────────────────────────────────────────────────────
	if c.afxdpSnapshotFn != nil {
		snap := c.afxdpSnapshotFn()
		c.afxdpRxPackets.Set(float64(snap.RxPackets))
		c.afxdpRxBytes.Set(float64(snap.RxBytes))
		c.afxdpParseErrors.Set(float64(snap.ParseErrors))
		c.afxdpUMEMExhaust.Set(float64(snap.UMEMExhausted))
		c.afxdpMetaChanLen.Set(float64(snap.MetaChLen))
	}

	// ── Honeypot ─────────────────────────────────────────────────────────
	if c.honeypotSessionFn != nil {
		c.honeypotActiveSessions.Set(float64(c.honeypotSessionFn()))
	}

	// ── System ───────────────────────────────────────────────────────────
	c.falxUptime.Set(time.Since(c.startTime).Seconds())
}

// ─── Helper: add delta to Counter ─────────────────────────────────────────────
func addCounter(c prometheus.Counter, delta uint64) {
	if delta > 0 {
		c.Add(float64(delta))
	}
}
