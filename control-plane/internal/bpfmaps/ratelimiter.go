// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Map write rate-limiter (control-plane/internal/bpfmaps/ratelimiter.go).
//              Protects BPF maps from being flooded by the AI engine or SOC
//              operators. A rogue AI inference loop could issue thousands of
//              map writes per second, causing kernel scheduler contention.
//
//              Design: Token bucket per operation type.
//                - Block/Unblock IP: 10,000 ops/sec max
//                - Config update:       100 ops/sec max (rare operation)
//                - Failsafe toggle:      10 ops/sec max (safety-critical)
//
//              Thread-safe: all operations protected by mutex + atomic counters.
// =============================================================================

package bpfmaps

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// ─── Operation Types ──────────────────────────────────────────────────────────
type MapOpType uint8

const (
	OpBlockIP      MapOpType = iota // Insert/update blocklist entry
	OpUnblockIP                     // Remove blocklist entry
	OpUpdateConfig                  // Write to CONFIG map
	OpFailsafe                      // Write to FAILSAFE_STATE map
	OpRateLimit                     // Write to RATE_LIMIT map
)

func (o MapOpType) String() string {
	switch o {
	case OpBlockIP:
		return "block_ip"
	case OpUnblockIP:
		return "unblock_ip"
	case OpUpdateConfig:
		return "update_config"
	case OpFailsafe:
		return "failsafe"
	case OpRateLimit:
		return "rate_limit"
	default:
		return "unknown"
	}
}

// ─── Per-Operation Rate Limit Config ─────────────────────────────────────────
type RateLimitConfig struct {
	// Maximum operations per second for each op type
	BlockIPRPS      int64
	UnblockIPRPS    int64
	UpdateConfigRPS int64
	FailsafeRPS     int64
	RateLimitRPS    int64
}

func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		BlockIPRPS:      10_000,
		UnblockIPRPS:    10_000,
		UpdateConfigRPS: 100,
		FailsafeRPS:     10,
		RateLimitRPS:    5_000,
	}
}

// ─── Token Bucket ─────────────────────────────────────────────────────────────
type tokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	capacity   float64
	refillRate float64 // tokens per nanosecond
	lastRefill time.Time
	dropped    atomic.Int64
	accepted   atomic.Int64
}

func newTokenBucket(rps int64) *tokenBucket {
	capacity := float64(rps)
	return &tokenBucket{
		tokens:     capacity,
		capacity:   capacity,
		refillRate: float64(rps) / float64(time.Second),
		lastRefill: time.Now(),
	}
}

// Allow returns true if the operation is permitted, false if rate-limited.
func (b *tokenBucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastRefill)
	b.lastRefill = now

	// Refill tokens based on elapsed time
	b.tokens += elapsed.Seconds() * float64(time.Second) * b.refillRate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}

	if b.tokens < 1.0 {
		b.dropped.Add(1)
		return false
	}

	b.tokens--
	b.accepted.Add(1)
	return true
}

// ─── Map Rate Limiter ─────────────────────────────────────────────────────────
type MapRateLimiter struct {
	buckets map[MapOpType]*tokenBucket
	log     *zap.Logger
}

func NewMapRateLimiter(cfg RateLimitConfig, log *zap.Logger) *MapRateLimiter {
	return &MapRateLimiter{
		log: log,
		buckets: map[MapOpType]*tokenBucket{
			OpBlockIP:      newTokenBucket(cfg.BlockIPRPS),
			OpUnblockIP:    newTokenBucket(cfg.UnblockIPRPS),
			OpUpdateConfig: newTokenBucket(cfg.UpdateConfigRPS),
			OpFailsafe:     newTokenBucket(cfg.FailsafeRPS),
			OpRateLimit:    newTokenBucket(cfg.RateLimitRPS),
		},
	}
}

// Check returns nil if the operation is allowed, or an error if rate-limited.
func (r *MapRateLimiter) Check(op MapOpType) error {
	bucket, ok := r.buckets[op]
	if !ok {
		return fmt.Errorf("unknown operation type: %d", op)
	}
	if !bucket.Allow() {
		r.log.Warn("Map write rate-limited",
			zap.String("op", op.String()),
			zap.Int64("total_dropped", bucket.dropped.Load()),
		)
		return fmt.Errorf("rate limit exceeded for operation %s", op.String())
	}
	return nil
}

// Stats returns current rate limiter statistics per operation type.
func (r *MapRateLimiter) Stats() map[string]map[string]int64 {
	result := make(map[string]map[string]int64, len(r.buckets))
	for op, bucket := range r.buckets {
		result[op.String()] = map[string]int64{
			"accepted": bucket.accepted.Load(),
			"dropped":  bucket.dropped.Load(),
		}
	}
	return result
}
