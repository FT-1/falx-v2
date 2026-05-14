// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Circuit breaker recovery manager (control-plane/internal/failsafe/recovery.go).
//              Controls the cooldown period and recovery probing strategy.
//
//              Recovery strategy:
//                1. Circuit opens → start cooldown timer
//                2. Cooldown expires → transition to HALF-OPEN
//                3. HALF-OPEN: monitor one polling interval
//                   a. Traffic normal → CLOSE circuit (restore AI path)
//                   b. Traffic still high → RE-TRIP with exponential backoff
//
//              Exponential backoff on repeated trips:
//                Trip 1: cooldown = base (30s)
//                Trip 2: cooldown = base * 2 (60s)
//                Trip 3: cooldown = base * 4 (120s)
//                ...
//                Max: 3600s (1 hour cap)
//
//              Backoff resets after the circuit stays closed for resetAfter duration.
// =============================================================================

package failsafe

import (
	"math"
	"time"
)

// ─── Recovery Config ──────────────────────────────────────────────────────────
type RecoveryConfig struct {
	// Base cooldown before attempting HALF-OPEN probe
	BaseCooldown time.Duration
	// Maximum cooldown after repeated trips (exponential backoff cap)
	MaxCooldown time.Duration
	// After circuit stays closed this long, reset the trip counter & backoff
	BackoffResetAfter time.Duration
	// How long to stay in HALF-OPEN before deciding
	HalfOpenProbeWindow time.Duration
}

func DefaultRecoveryConfig() RecoveryConfig {
	return RecoveryConfig{
		BaseCooldown:        30 * time.Second,
		MaxCooldown:         3600 * time.Second, // 1 hour max
		BackoffResetAfter:   5 * time.Minute,
		HalfOpenProbeWindow: 5 * time.Second,
	}
}

// ─── Recovery Manager ─────────────────────────────────────────────────────────
type RecoveryManager struct {
	cfg RecoveryConfig
}

func NewRecoveryManager(cfg RecoveryConfig) *RecoveryManager {
	return &RecoveryManager{cfg: cfg}
}

// CooldownFor computes the cooldown duration for a given trip count.
// Uses exponential backoff capped at MaxCooldown.
// Hardening (F8): cap the multiplier BEFORE pow/cast — otherwise
// 2^N * BaseCooldown can overflow int64 around trips≈40 and produce
// negative durations (recovery would either fire every tick or never).
func (r *RecoveryManager) CooldownFor(tripCount int) time.Duration {
	if tripCount <= 1 {
		return r.cfg.BaseCooldown
	}
	// Compute the highest multiplier that would NOT overflow MaxCooldown.
	// log2(MaxCooldown / BaseCooldown) gives the safe shift cap.
	maxMult := float64(r.cfg.MaxCooldown) / float64(r.cfg.BaseCooldown)
	if maxMult < 1 {
		return r.cfg.BaseCooldown
	}
	maxShift := int(math.Log2(maxMult)) + 1
	shift := tripCount - 1
	if shift > maxShift {
		shift = maxShift
	}
	multiplier := math.Pow(2.0, float64(shift))
	d := time.Duration(float64(r.cfg.BaseCooldown) * multiplier)
	if d > r.cfg.MaxCooldown || d < 0 {
		d = r.cfg.MaxCooldown
	}
	return d
}

// ShouldAttemptRecovery returns true if enough time has passed since the
// circuit opened to attempt a HALF-OPEN probe.
func (r *RecoveryManager) ShouldAttemptRecovery(openedAt time.Time, tripCount int) bool {
	cooldown := r.CooldownFor(tripCount)
	return time.Since(openedAt) >= cooldown
}

// ShouldResetBackoff returns true if the circuit has been stable long enough
// to reset the exponential backoff multiplier.
func (r *RecoveryManager) ShouldResetBackoff(lastClosedAt time.Time) bool {
	return !lastClosedAt.IsZero() &&
		time.Since(lastClosedAt) >= r.cfg.BackoffResetAfter
}

// HalfOpenExpired returns true if the HALF-OPEN probe window has elapsed
// without a re-trip (meaning we can safely close the circuit).
func (r *RecoveryManager) HalfOpenExpired(halfOpenAt time.Time) bool {
	return time.Since(halfOpenAt) >= r.cfg.HalfOpenProbeWindow
}
