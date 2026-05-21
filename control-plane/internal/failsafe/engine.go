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
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/ft-1/falx-v2/control-plane/pkg/bpfmaps"
	"github.com/ft-1/falx-v2/control-plane/pkg/events"
)

// ─── Admin Override Latch ─────────────────────────────────────────────────────
// adminOverrideCooldown is how long algorithmic tripping is suppressed after a
// manual ForceClose. Long enough to outlast a sustained flood's cumulative-drop
// ratio (which stays near 100% for the duration of the attack).
const (
	adminOverrideCooldown  = 5 * time.Minute
	adminOverrideLatchPath = "/run/falx/admin_override"
)

// adminOverrideLatch suppresses automatic circuit tripping for a fixed window
// after a SOC operator forces the circuit closed. Both in-process (via
// overrideCh) and cross-process (via sentinel file from falx-soc) paths arm it.
type adminOverrideLatch struct {
	mu     sync.Mutex
	active bool
	until  time.Time
}

func (l *adminOverrideLatch) Arm(d time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.active = true
	l.until  = time.Now().Add(d)
}

func (l *adminOverrideLatch) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.active = false
	l.until  = time.Time{}
}

func (l *adminOverrideLatch) IsActive() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.active {
		return false
	}
	if time.Now().After(l.until) {
		l.active = false
		return false
	}
	return true
}

func (l *adminOverrideLatch) ExpiresAt() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.until
}

// adminOverrideFileActive checks whether the cross-process sentinel file exists
// and was written within the adminOverrideCooldown window. falx-soc touches this
// file when ForceCloseCircuit is called so that the engine (running in falxd)
// suppresses algorithmic re-tripping even across the process boundary.
func adminOverrideFileActive() bool {
	fi, err := os.Stat(adminOverrideLatchPath)
	if err != nil {
		return false
	}
	return time.Since(fi.ModTime()) < adminOverrideCooldown
}

func touchAdminOverrideFile() {
	dir := "/run/falx"
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(adminOverrideLatchPath, []byte("1"), 0o644)
}

// ErrEngineBusy is returned by ForceOpen/ForceClose/UpdateThresholds when the
// engine's override channel is full — the engine goroutine is stalled and the
// caller (typically a SOC API handler) MUST surface this rather than block.
var ErrEngineBusy = errors.New("failsafe engine override channel full — try again")

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
	cfgMu    sync.RWMutex // Guards cfg.Detector (hot-reloaded via UpdateThresholds)
	cfg      EngineConfig
	mgr      *bpfmaps.Manager
	cb       *CircuitBreaker
	detector *Detector
	recovery *RecoveryManager
	log      *zap.Logger

	// Optional bus for cross-subsystem notifications (SOC dashboard, audit).
	// nil-safe: all emit sites guard with `if e.bus != nil`.
	bus *events.Bus

	// Exposed channel for SOC backend to consume state transitions
	Transitions <-chan StateTransition

	// Counters for Prometheus metrics
	totalTrips        atomic.Uint64
	totalCloses       atomic.Uint64
	bpfWriteFailures  atomic.Uint64 // F10: track BPF write errors (kernel/CP divergence)

	// Manual override channel (SOC operator can force open/close)
	overrideCh chan overrideCmd

	// Admin override latch: suppresses algorithmic tripping after ForceClose.
	// Checked on every tickClosed() call.
	adminLatch adminOverrideLatch

	// Track last-closed time for backoff reset
	lastClosedAt time.Time
	halfOpenAt   time.Time
}

// overrideKind discriminates the override channel payload so a threshold-update
// no longer accidentally triggers a Close() (audit finding F1).
type overrideKind uint8

const (
	overrideForceOpen overrideKind = iota
	overrideForceClose
	overrideThresholdUpdate
)

type overrideCmd struct {
	kind         overrideKind
	reason       string
	ppsThreshold uint64 // valid only for overrideThresholdUpdate
	bpsThreshold uint64
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

// SetBus wires an events.Bus so the engine can publish CircuitOpen/Closed
// notifications for SOC dashboards. Must be called before Run.
// Optional — nil bus disables external notifications (legacy callers).
func (e *Engine) SetBus(bus *events.Bus) {
	e.bus = bus
}

// publishTransition emits a Bus event for a state transition.
// nil-safe: silently no-op if no bus was wired (audit finding F3).
func (e *Engine) publishTransition(from, to CircuitState, reason string, pps uint64) {
	if e.bus == nil {
		return
	}
	switch to {
	case StateOpen:
		e.bus.Publish(events.CircuitOpenEvent(pps, reason))
	case StateClosed:
		e.bus.Publish(events.CircuitClosedEvent(pps))
	}
}

// ─── Run ──────────────────────────────────────────────────────────────────────
// Run starts the polling loop. Blocks until ctx is cancelled.
// Hardening (F14): a defer/recover wrapper turns a tick panic into a logged
// error + immediate restart rather than silently killing the entire failsafe
// goroutine (which would leave the kernel autonomous detector as the only
// remaining defense layer).
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
			e.safeApplyOverride(cmd)

		case <-ticker.C:
			e.safeTick()
		}
	}
}

// safeTick wraps tick() with panic recovery. A panic in the detector or BPF
// read path must NOT kill the failsafe goroutine — without it, kernel
// autonomous detection becomes the only line of defense (a single layer
// instead of defense-in-depth).
func (e *Engine) safeTick() {
	defer func() {
		if r := recover(); r != nil {
			e.log.Error("Failsafe tick panicked — recovering",
				zap.Any("panic", r))
		}
	}()
	e.tick()
}

func (e *Engine) safeApplyOverride(cmd overrideCmd) {
	defer func() {
		if r := recover(); r != nil {
			e.log.Error("Failsafe applyOverride panicked — recovering",
				zap.Any("panic", r))
		}
	}()
	e.applyOverride(cmd)
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
	// Admin override latch: a SOC operator manually closed the circuit.
	// Suppress algorithmic re-tripping for the cooldown window (5 min) so
	// that cumulative drop-ratio > 90% (always high during an ongoing attack)
	// does not instantly re-open the circuit after the operator's action.
	// Keep feeding stats to the detector so the EMA baseline stays fresh.
	if e.adminLatch.IsActive() || adminOverrideFileActive() {
		e.detector.Analyze(stats)
		e.cb.ResetViolation()
		return
	}

	results := e.detector.Analyze(stats)

	// Check backoff reset eligibility
	if !e.lastClosedAt.IsZero() && e.recovery.ShouldResetBackoff(e.lastClosedAt) {
		if e.cb.TripCount() > 0 {
			e.log.Info("Exponential backoff reset — circuit stable for required duration")
			// Hardening (F6): use the exported encapsulated reset so future
			// CircuitBreaker locking-strategy changes don't silently break us.
			e.cb.ResetTripCount()
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

	// F3: Emit Bus event so SOC dashboards / audit log see the transition.
	e.publishTransition(StateClosed, StateOpen, r.Reason, r.CurrentPPS)

	// Write to FAILSAFE_STATE BPF map — XDP will read this on next packet
	if err := e.mgr.SetCircuitOpen(true, r.Reason); err != nil {
		// F10: track BPF write failures (kernel/CP divergence).
		// Defense-in-depth: kernel XDP has its own autonomous detector
		// (main.rs:128-149) that opens the circuit if pps/bps exceeds its
		// own thresholds. We rely on that as the safety net but loudly
		// alert so operators can investigate the divergence.
		e.bpfWriteFailures.Add(1)
		e.log.Error("Failed to open circuit in BPF map — relying on kernel autonomous detection",
			zap.Error(err),
			zap.Uint64("bpf_write_failures_total", e.bpfWriteFailures.Load()),
		)
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

	// F3: Emit Bus event so SOC dashboards / audit log see the transition.
	e.publishTransition(StateOpen, StateClosed, "traffic_normalized", pps)

	// Write to FAILSAFE_STATE BPF map — XDP resumes passing to AI
	if err := e.mgr.SetCircuitOpen(false, "traffic_normalized"); err != nil {
		// F10: critical divergence — kernel may still be dropping while
		// the control plane thinks the circuit is closed.
		e.bpfWriteFailures.Add(1)
		e.log.Error("Failed to close circuit in BPF map — kernel may still drop traffic",
			zap.Error(err),
			zap.Uint64("bpf_write_failures_total", e.bpfWriteFailures.Load()),
		)
	}
}

// ─── SOC Manual Override ──────────────────────────────────────────────────────

// ForceOpen allows a SOC operator to manually open the circuit (emergency).
// Hardening (F2): non-blocking send — if the engine goroutine is stalled
// (e.g. blocked on a slow BPF syscall) the API handler MUST surface ErrEngineBusy
// instead of blocking the operator's emergency lever.
func (e *Engine) ForceOpen(reason string) error {
	select {
	case e.overrideCh <- overrideCmd{kind: overrideForceOpen, reason: "soc_manual:" + reason}:
		return nil
	default:
		return ErrEngineBusy
	}
}

// ForceClose allows a SOC operator to manually close the circuit.
func (e *Engine) ForceClose(reason string) error {
	select {
	case e.overrideCh <- overrideCmd{kind: overrideForceClose, reason: "soc_manual:" + reason}:
		return nil
	default:
		return ErrEngineBusy
	}
}

func (e *Engine) applyOverride(cmd overrideCmd) {
	switch cmd.kind {

	case overrideForceOpen:
		e.log.Warn("SOC manual circuit OPEN", zap.String("reason", cmd.reason))
		e.adminLatch.Clear()
		_ = os.Remove(adminOverrideLatchPath) // clear cross-process sentinel
		if e.cb.Trip(cmd.reason, 0, 0) {
			e.publishTransition(StateClosed, StateOpen, cmd.reason, 0)
		}
		if err := e.mgr.SetCircuitOpen(true, cmd.reason); err != nil {
			e.bpfWriteFailures.Add(1)
			e.log.Error("ForceOpen BPF write failed", zap.Error(err))
		}

	case overrideForceClose:
		e.log.Warn("SOC manual circuit CLOSE", zap.String("reason", cmd.reason))
		e.adminLatch.Arm(adminOverrideCooldown)
		touchAdminOverrideFile() // arm cross-process sentinel for falx-soc path
		if e.cb.Close(0, 0) {
			e.publishTransition(StateOpen, StateClosed, cmd.reason, 0)
		}
		if err := e.mgr.SetCircuitOpen(false, cmd.reason); err != nil {
			e.bpfWriteFailures.Add(1)
			e.log.Error("ForceClose BPF write failed", zap.Error(err))
		}
		e.lastClosedAt = time.Now()

	case overrideThresholdUpdate:
		// F1: actually update the in-process detector config — the old code
		// sent a misleading {open:false} cmd which spuriously closed the circuit
		// AND never updated e.cfg.Detector / e.detector.cfg, so the detector
		// kept using the original thresholds.
		e.cfgMu.Lock()
		e.cfg.Detector.PPSThreshold = cmd.ppsThreshold
		e.cfg.Detector.BPSThreshold = cmd.bpsThreshold
		e.detector.UpdateThresholds(cmd.ppsThreshold, cmd.bpsThreshold)
		e.cfgMu.Unlock()
		e.log.Info("Failsafe thresholds applied",
			zap.Uint64("pps", cmd.ppsThreshold),
			zap.Uint64("bps", cmd.bpsThreshold),
			zap.String("reason", cmd.reason),
		)
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
	Circuit              CircuitSnapshot
	Baseline             DetectorBaseline
	TotalTrips           uint64
	TotalCloses          uint64
	PollInterval         time.Duration
	AdminOverrideActive  bool
	AdminOverrideExpires time.Time
}

func (e *Engine) Metrics() EngineMetrics {
	return EngineMetrics{
		Circuit:              e.cb.Snapshot(),
		Baseline:             e.detector.Baseline(),
		TotalTrips:           e.totalTrips.Load(),
		TotalCloses:          e.totalCloses.Load(),
		PollInterval:         e.cfg.PollInterval,
		AdminOverrideActive:  e.adminLatch.IsActive() || adminOverrideFileActive(),
		AdminOverrideExpires: e.adminLatch.ExpiresAt(),
	}
}

// ─── Thresholds Update (hot-reload without restart) ───────────────────────────
// UpdateThresholds is safe to call concurrently: it sends the new config via
// overrideCh so the engine's single polling goroutine applies it without races.
// Hardening (F1): uses a dedicated overrideThresholdUpdate kind so it no longer
// triggers a spurious circuit Close as a side-effect.
// Hardening (F2): non-blocking — returns ErrEngineBusy if the engine is stalled
// rather than blocking the SOC API handler forever.
func (e *Engine) UpdateThresholds(ppsThr, bpsThr uint64) error {
	select {
	case e.overrideCh <- overrideCmd{
		kind:         overrideThresholdUpdate,
		reason:       fmt.Sprintf("threshold_update pps=%d bps=%d", ppsThr, bpsThr),
		ppsThreshold: ppsThr,
		bpsThreshold: bpsThr,
	}:
	default:
		return ErrEngineBusy
	}
	e.log.Info("Failsafe threshold update queued",
		zap.Uint64("pps_threshold", ppsThr),
		zap.Uint64("bps_threshold", bpsThr),
	)
	// Also push to kernel so XDP's autonomous detector uses the same numbers.
	return e.mgr.UpdateFailsafeThresholds(ppsThr, bpsThr)
}

// BPFWriteFailures exposes the running counter for Prometheus / SOC telemetry.
// A non-zero value means the kernel and control-plane circuit views may have
// diverged — operators should investigate.
func (e *Engine) BPFWriteFailures() uint64 {
	return e.bpfWriteFailures.Load()
}
