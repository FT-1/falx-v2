// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Circuit breaker state machine (control-plane/internal/failsafe/state.go).
//              Implements the canonical three-state circuit breaker pattern
//              adapted for a high-throughput network security context.
//
//              State transitions:
//
//                ┌─────────────────────────────────────────────────────┐
//                │                                                     │
//                ▼                                                     │
//           ┌─────────┐   flood detected    ┌──────────┐              │
//           │ CLOSED  │ ─────────────────► │   OPEN   │              │
//           │(normal) │                    │(drop all)│              │
//           └─────────┘ ◄───────────────── └──────────┘              │
//                ▲         flood cleared          │                   │
//                │                               │ cooldown expires   │
//                │                               ▼                   │
//                │                        ┌────────────┐             │
//                └────────────────────────│ HALF-OPEN  │─────────────┘
//                    traffic normal        │ (sampling) │  flood recurs
//                                         └────────────┘
//
//              Hysteresis: circuit only opens when threshold exceeded for
//              ConsecutiveViolations ticks (prevents flapping on bursts).
//              Recovery: exponential backoff on repeated trips.
// =============================================================================

package failsafe

import (
	"fmt"
	"sync"
	"time"
)

// ─── Circuit States ───────────────────────────────────────────────────────────
type CircuitState uint8

const (
	// StateClosed = normal operation; AI inference active; XDP passes to stack
	StateClosed CircuitState = iota
	// StateOpen = DDoS flood mode; AI bypassed; XDP drops all unknown traffic
	StateOpen
	// StateHalfOpen = cooldown expired; testing if flood has subsided
	// A single traffic sample is let through to the AI engine
	StateHalfOpen
)

func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateOpen:
		return "OPEN"
	case StateHalfOpen:
		return "HALF_OPEN"
	default:
		return "UNKNOWN"
	}
}

// ─── State Transition Event ───────────────────────────────────────────────────
type StateTransition struct {
	From      CircuitState
	To        CircuitState
	At        time.Time
	Reason    string
	CurrentPPS uint64
	CurrentBPS uint64
	TripCount  int // How many times circuit has opened since last reset
}

func (t StateTransition) String() string {
	return fmt.Sprintf("[%s → %s] at %s | reason=%q | pps=%d | trips=%d",
		t.From, t.To, t.At.Format(time.RFC3339), t.Reason,
		t.CurrentPPS, t.TripCount)
}

// ─── Circuit Breaker State Machine ────────────────────────────────────────────
type CircuitBreaker struct {
	mu    sync.RWMutex
	state CircuitState

	// Timestamps
	openedAt    time.Time
	halfOpenAt  time.Time
	lastClosedAt time.Time

	// Trip counter (for exponential backoff on cooldown)
	tripCount int

	// Consecutive threshold violations before opening (hysteresis)
	violations int

	// Transition event channel — consumed by Engine and SOC backend
	transitions chan StateTransition
}

func newCircuitBreaker() *CircuitBreaker {
	return &CircuitBreaker{
		state:       StateClosed,
		transitions: make(chan StateTransition, 256),
	}
}

// ─── State Queries ────────────────────────────────────────────────────────────

func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

func (cb *CircuitBreaker) IsOpen() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state == StateOpen
}

func (cb *CircuitBreaker) IsHalfOpen() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state == StateHalfOpen
}

func (cb *CircuitBreaker) TripCount() int {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.tripCount
}

// OpenDuration returns how long the circuit has been open (0 if not open).
func (cb *CircuitBreaker) OpenDuration() time.Duration {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	if cb.state == StateOpen || cb.state == StateHalfOpen {
		return time.Since(cb.openedAt)
	}
	return 0
}

// ─── Transitions ──────────────────────────────────────────────────────────────

// Trip opens the circuit. Called when flood thresholds are exceeded.
// Returns true if the transition actually happened (guards against double-trips).
func (cb *CircuitBreaker) Trip(reason string, pps, bps uint64) bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == StateOpen {
		return false // Already open
	}

	prev := cb.state
	cb.state    = StateOpen
	cb.openedAt = time.Now()
	cb.tripCount++
	cb.violations = 0 // Reset hysteresis counter

	cb.emit(StateTransition{
		From:       prev,
		To:         StateOpen,
		At:         cb.openedAt,
		Reason:     reason,
		CurrentPPS: pps,
		CurrentBPS: bps,
		TripCount:  cb.tripCount,
	})
	return true
}

// AttemptRecovery transitions OPEN → HALF_OPEN.
// Called when the cooldown period has expired.
func (cb *CircuitBreaker) AttemptRecovery(pps, bps uint64) bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state != StateOpen {
		return false
	}

	cb.state     = StateHalfOpen
	cb.halfOpenAt = time.Now()

	cb.emit(StateTransition{
		From:       StateOpen,
		To:         StateHalfOpen,
		At:         cb.halfOpenAt,
		Reason:     "cooldown_expired",
		CurrentPPS: pps,
		CurrentBPS: bps,
		TripCount:  cb.tripCount,
	})
	return true
}

// Close transitions HALF_OPEN → CLOSED (flood has cleared).
func (cb *CircuitBreaker) Close(pps, bps uint64) bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == StateClosed {
		return false
	}

	prev := cb.state
	cb.state       = StateClosed
	cb.lastClosedAt = time.Now()

	cb.emit(StateTransition{
		From:       prev,
		To:         StateClosed,
		At:         cb.lastClosedAt,
		Reason:     "traffic_normalized",
		CurrentPPS: pps,
		CurrentBPS: bps,
		TripCount:  cb.tripCount,
	})
	return true
}

// ReTrip transitions HALF_OPEN → OPEN (flood recurred during recovery probe).
func (cb *CircuitBreaker) ReTrip(reason string, pps, bps uint64) bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state != StateHalfOpen {
		return false
	}

	cb.state    = StateOpen
	cb.openedAt = time.Now() // Reset timer for new cooldown
	cb.tripCount++
	cb.violations = 0

	cb.emit(StateTransition{
		From:       StateHalfOpen,
		To:         StateOpen,
		At:         cb.openedAt,
		Reason:     "recovery_failed_" + reason,
		CurrentPPS: pps,
		CurrentBPS: bps,
		TripCount:  cb.tripCount,
	})
	return true
}

// IncrViolation increments the hysteresis counter.
// Returns true if the violation count has reached the threshold.
func (cb *CircuitBreaker) IncrViolation(threshold int) bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.violations++
	return cb.violations >= threshold
}

// ResetViolation resets the hysteresis counter (traffic is normal).
// Hardening: full reset to 0 (not decrement) — otherwise alternating
// good/bad ticks oscillate around N-1 and never trip during sustained
// moderate floods (audit finding F9).
func (cb *CircuitBreaker) ResetViolation() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.violations = 0
}

// ResetTripCount clears the trip counter (used after long stable period).
// Encapsulates the counter mutation so engine code doesn't reach into cb internals.
func (cb *CircuitBreaker) ResetTripCount() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.tripCount = 0
}

// ─── Transition Events ────────────────────────────────────────────────────────
func (cb *CircuitBreaker) Transitions() <-chan StateTransition {
	return cb.transitions
}

func (cb *CircuitBreaker) emit(t StateTransition) {
	select {
	case cb.transitions <- t:
	default:
		// Drop if channel full — SOC backend is too slow; not a safety issue
	}
}

// ─── Snapshot ─────────────────────────────────────────────────────────────────
type CircuitSnapshot struct {
	State        string
	TripCount    int
	OpenDuration time.Duration
	OpenedAt     time.Time
	Violations   int
}

func (cb *CircuitBreaker) Snapshot() CircuitSnapshot {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	dur := time.Duration(0)
	if cb.state != StateClosed {
		dur = time.Since(cb.openedAt)
	}
	return CircuitSnapshot{
		State:        cb.state.String(),
		TripCount:    cb.tripCount,
		OpenDuration: dur,
		OpenedAt:     cb.openedAt,
		Violations:   cb.violations,
	}
}
