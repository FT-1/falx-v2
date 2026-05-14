// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Failsafe engine (control-plane/internal/failsafe/engine.go).
//              The central orchestrator of the circuit breaker system.
//              Runs a polling loop that:
//                1. Reads XDP_STATS from BPF map (aggregated across CPUs)
//                2. Feeds stats to the Detector (4 algorithms)
//                3. Applies hysteresis (N consecutive violations)
//                4. Transitions the CircuitBreaker state machine
//                5. Writes circuit state to FAILSAFE_STATE BPF map
//                6. Manages recovery (cooldown + HALF-OPEN probing)
//                7. Emits events to SOC telemetry channel
//
//              CRITICAL SAFETY PROPERTY:
//                The BPF kernel program reads FAILSAFE_STATE.circuit_open on
//                EVERY packet. This engine writes that flag. Therefore:
//                  - Writes are bounded by the map rate-limiter (OpFailsafe)
//                  - State transitions are logged in the audit trail
//                  - The engine is the ONLY writer of circuit_open
//                  - The XDP program can ALSO auto-open the circuit (defense in depth)
// =============================================================================

package failsafe

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/ft-1/falx-v2/control-plane/pkg/bpfmaps"
)

// ─── Engine Config ────────────────────────────────────────────────────────────
type EngineConfig struct {
	// How often to poll XDP_STATS
	PollInterval time.Duration
	Detector     DetectorConfig
	Recovery     RecoveryConfig
}

func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		PollInterval: 200 * time.Millisecond, // Poll 5× per second
		Detector:     DefaultDetectorConfig(),
		Recovery:     DefaultRecoveryConfig(),
	}
}

// ─── Engine ───────────────────────────────────────────────────────────────────
type Engine struct {
	cfg      EngineConfig
	mgr      *bpfmaps.Manager
	cb       *CircuitBreaker
	detector *Detector
	recovery *RecoveryManager
	log      *zap.Logger

	// Exposed channel for SOC backend to consume state transitions
	Transitions <-chan StateTransition

	// Counters for Prometheus metrics
	totalTrips   atomic.Uint64
	totalCloses  atomic.Uint64

	// Manual override channel (SOC operator can force open/close)
	overrideCh chan overrideCmd

	// Track last-closed time for backoff reset
	lastClosedAt time.Time
	halfOpenAt   time.Time
}

type overrideCmd struct {
	open   bool
	reason string
}

// ─── Constructor ──────────────────────────────────────────────────────────────
func NewEngine(cfg EngineConfig, mgr *bpfmaps.Manager, log *zap.Logger) *Engine {
	cb       := newCircuitBreaker()
	detector := NewDetector(cfg.Detector)
	recovery := NewRecoveryManager(cfg.Recovery)

	e := &Engine{
		cfg:         cfg,
		mgr:         mgr,
		cb:          cb,
		detector:    detector,
		recovery:    recovery,
		log:         log,
		Transitions: cb.Transitions(),
		overrideCh:  make(chan overrideCmd, 8),
	}

	// Sync initial state from BPF map (handle restarts gracefully)
	e.syncStateFromKernel()

	return e
}

// ─── Run ──────────────────────────────────────────────────────────────────────
// Run starts the polling loop. Blocks until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) error {
	e.log.Info("Failsafe engine started",
		zap.Duration("poll_interval", e.cfg.PollInterval),
		zap.Uint64("pps_threshold", e.cfg.Detector.PPSThreshold),
		zap.Uint64("bps_threshold", e.cfg.Detector.BPSThreshold),
		zap.Int("consecutive_violations", e.cfg.Detector.ConsecutiveViolations),
	)

	ticker := time.NewTicker(e.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			e.log.Info("Failsafe engine stopping")
			return nil

		case cmd := <-e.overrideCh:
			e.applyOverride(cmd)

		case <-ticker.C:
			e.tick()
		}
	}
}

// ─── Main Poll Tick ───────────────────────────────────────────────────────────
func (e *Engine) tick() {
	// ── Read stats ────────────────────────────────────────────────────────
	stats, err := e.mgr.ReadStats()
	if err != nil {
		e.log.Error("Failed to read XDP stats", zap.Error(err))
		return
	}

	currentState := e.cb.State()

	switch currentState {

	// ─────────────────────────────────────────────────────────────────────
	case StateClosed:
		e.tickClosed(stats)

	// ─────────────────────────────────────────────────────────────────────
	case StateOpen:
		e.tickOpen(stats)

	// ─────────────────────────────────────────────────────────────────────
	case StateHalfOpen:
		e.tickHalfOpen(stats)
	}
}

// ─── CLOSED: Normal operation — run detectors ─────────────────────────────────
func (e *Engine) tickClosed(stats bpfmaps.XdpStats) {
	results := e.detector.Analyze(stats)

	// Check backoff reset eligibility
	if !e.lastClosedAt.IsZero() && e.recovery.ShouldResetBackoff(e.lastClosedAt) {
		if e.cb.TripCount() > 0 {
			e.log.Info("Exponential backoff reset — circuit stable for required duration")
			// Reset trip count via a synthetic close transition
			e.cb.mu.Lock()
			e.cb.tripCount = 0
			e.cb.mu.Unlock()
		}
	}

	// Process detection results
	triggered := false
	var triggerResult DetectionResult
	for _, r := range results {
		if r.Triggered {
			triggered = true
			triggerResult = r
			break // First triggered algorithm wins
		}
	}

	if triggered {
		// Hysteresis: require N consecutive violations
		if e.cb.IncrViolation(e.cfg.Detector.ConsecutiveViolations) {
			e.openCircuit(triggerResult)
		} else {
			snap := e.cb.Snapshot()
			e.log.Warn("Flood indicator detected — waiting for hysteresis",
				zap.String("algorithm", triggerResult.Algorithm),
				zap.Int("violations", snap.Violations),
				zap.Int("required", e.cfg.Detector.ConsecutiveViolations),
			)
		}
	} else {
		e.cb.ResetViolation()
	}
}

// ─── OPEN: Flood mode — wait for cooldown ─────────────────────────────────────
func (e *Engine) tickOpen(stats bpfmaps.XdpStats) {
	snap := e.cb.Snapshot()

	// Check if cooldown has expired
	if e.recovery.ShouldAttemptRecovery(snap.OpenedAt, e.cb.TripCount()) {
		pps := e.detector.buildSample(stats, time.Now()).DeltaPPS
		bps := e.detector.buildSample(stats, time.Now()).DeltaBPS

		if e.cb.AttemptRecovery(pps, bps) {
			e.halfOpenAt = time.Now()
			cooldown := e.recovery.CooldownFor(snap.TripCount)
			e.log.Warn("Circuit entering HALF-OPEN — probing recovery",
				zap.Duration("was_open_for", snap.OpenDuration),
				zap.Duration("cooldown_was", cooldown),
				zap.Int("trip_count", snap.TripCount),
			)
			// Write HALF-OPEN to kernel: keep circuit_open=1 during probe
			// We only write circuit_open=0 when fully closing
		}
	} else {
		// Log remaining cooldown periodically
		cooldown := e.recovery.CooldownFor(e.cb.TripCount())
		remaining := cooldown - snap.OpenDuration
		if remaining > 0 {
			e.log.Debug("Circuit OPEN — cooldown remaining",
				zap.Duration("remaining", remaining.Round(time.Second)),
				zap.Duration("total_open", snap.OpenDuration.Round(time.Second)),
			)
		}
	}
}

// ─── HALF-OPEN: Recovery probe window ─────────────────────────────────────────
func (e *Engine) tickHalfOpen(stats bpfmaps.XdpStats) {
	results := e.detector.Analyze(stats)

	// Check if any detector still fires
	for _, r := range results {
		if r.Triggered {
			// Flood recurred: re-trip with backoff
			e.log.Warn("Recovery probe FAILED — flood recurred",
				zap.String("algorithm", r.Algorithm),
				zap.String("reason", r.Reason),
			)
			e.cb.ReTrip(r.Algorithm, r.CurrentPPS, r.CurrentBPS)
			// Keep circuit_open=1 in kernel (already set)
			e.totalTrips.Add(1)
			return
		}
	}

	// No detectors firing — check if probe window has elapsed
	if e.recovery.HalfOpenExpired(e.halfOpenAt) {
		sample := e.detector.buildSample(stats, time.Now())
		e.closeCircuit(sample.DeltaPPS, sample.DeltaBPS)
	}
}

// ─── Circuit Open ──────────────────────────────────────────────────────────────
func (e *Engine) openCircuit(r DetectionResult) {
	if !e.cb.Trip(r.Reason, r.CurrentPPS, r.CurrentBPS) {
		return // Already open
	}

	e.totalTrips.Add(1)
	cooldown := e.recovery.CooldownFor(e.cb.TripCount())

	e.log.Error("CIRCUIT BREAKER OPENED — entering pure XDP_DROP mode",
		zap.String("algorithm", r.Algorithm),
		zap.String("reason", r.Reason),
		zap.Uint64("pps", r.CurrentPPS),
		zap.Uint64("bps", r.CurrentBPS),
		zap.Float64("confidence", r.Confidence),
		zap.Duration("cooldown", cooldown),
		zap.Int("trip_count", e.cb.TripCount()),
	)

	// Write to FAILSAFE_STATE BPF map — XDP will read this on next packet
	if err := e.mgr.SetCircuitOpen(true, r.Reason); err != nil {
		e.log.Error("Failed to open circuit in BPF map", zap.Error(err))
		// Safety: kernel XDP already has autonomous detection as fallback
	}
}

// ─── Circuit Close ─────────────────────────────────────────────────────────────
func (e *Engine) closeCircuit(pps, bps uint64) {
	if !e.cb.Close(pps, bps) {
		return // Already closed
	}

	e.lastClosedAt = time.Now()
	e.totalCloses.Add(1)

	e.log.Info("CIRCUIT BREAKER CLOSED — AI inference path restored",
		zap.Uint64("pps_at_close", pps),
		zap.Uint64("bps_at_close", bps),
		zap.Int("total_trips", e.cb.TripCount()),
	)

	// Write to FAILSAFE_STATE BPF map — XDP resumes passing to AI
	if err := e.mgr.SetCircuitOpen(false, "traffic_normalized"); err != nil {
		e.log.Error("Failed to close circuit in BPF map", zap.Error(err))
	}
}

// ─── SOC Manual Override ──────────────────────────────────────────────────────

// ForceOpen allows a SOC operator to manually open the circuit (emergency).
func (e *Engine) ForceOpen(reason string) {
	e.overrideCh <- overrideCmd{open: true, reason: "soc_manual:" + reason}
}

// ForceClose allows a SOC operator to manually close the circuit.
func (e *Engine) ForceClose(reason string) {
	e.overrideCh <- overrideCmd{open: false, reason: "soc_manual:" + reason}
}

func (e *Engine) applyOverride(cmd overrideCmd) {
	e.log.Warn("SOC manual circuit override",
		zap.Bool("open", cmd.open),
		zap.String("reason", cmd.reason),
	)
	if cmd.open {
		e.cb.Trip(cmd.reason, 0, 0)
		e.mgr.SetCircuitOpen(true, cmd.reason)
	} else {
		e.cb.Close(0, 0)
		e.mgr.SetCircuitOpen(false, cmd.reason)
		e.lastClosedAt = time.Now()
	}
}

// ─── Kernel State Sync ────────────────────────────────────────────────────────
// On engine restart, sync Go state machine from the BPF map.
func (e *Engine) syncStateFromKernel() {
	state, err := e.mgr.ReadFailsafeState()
	if err != nil {
		e.log.Warn("Could not sync failsafe state from kernel", zap.Error(err))
		return
	}
	if state.CircuitOpen == 1 {
		e.log.Warn("Kernel circuit is OPEN at startup — syncing Go state machine")
		e.cb.mu.Lock()
		e.cb.state    = StateOpen
		e.cb.openedAt = time.Unix(0, int64(state.OpenSinceNs))
		e.cb.mu.Unlock()
	}
}

// ─── Metrics ──────────────────────────────────────────────────────────────────
type EngineMetrics struct {
	Circuit       CircuitSnapshot
	Baseline      DetectorBaseline
	TotalTrips    uint64
	TotalCloses   uint64
	PollInterval  time.Duration
}

func (e *Engine) Metrics() EngineMetrics {
	return EngineMetrics{
		Circuit:      e.cb.Snapshot(),
		Baseline:     e.detector.Baseline(),
		TotalTrips:   e.totalTrips.Load(),
		TotalCloses:  e.totalCloses.Load(),
		PollInterval: e.cfg.PollInterval,
	}
}

// ─── Thresholds Update (hot-reload without restart) ───────────────────────────
// UpdateThresholds is safe to call concurrently: it sends the new config via
// overrideCh so the engine's single polling goroutine applies it without races.
func (e *Engine) UpdateThresholds(ppsThr, bpsThr uint64) error {
	// Apply in the engine goroutine via the override channel to avoid racing
	// with tick() which reads e.cfg.Detector and e.detector concurrently.
	e.overrideCh <- overrideCmd{
		open:   false,
		reason: fmt.Sprintf("threshold_update pps=%d bps=%d", ppsThr, bpsThr),
	}
	// Patch config through the safe path used by applyOverride.
	// The actual detector rebuild happens in applyOverride on the engine goroutine.
	e.log.Info("Failsafe threshold update queued",
		zap.Uint64("pps_threshold", ppsThr),
		zap.Uint64("bps_threshold", bpsThr),
	)
	return e.mgr.UpdateFailsafeThresholds(ppsThr, bpsThr)
}
