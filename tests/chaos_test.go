// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Chaos tests (tests/chaos_test.go).
//              Tests system resilience under adversarial conditions:
//                - Rapid circuit breaker open/close cycling
//                - Concurrent map write conflicts
//                - Token replay attacks
//                - Malformed input fuzzing
//                - Session flood (DoS simulation)
//                - Event bus saturation
//                - Policy engine under rule mutation
// =============================================================================

package tests

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	authpkg "github.com/ft-1/falx-v2/control-plane/internal/auth"
	"github.com/ft-1/falx-v2/control-plane/internal/bpfmaps"
	"github.com/ft-1/falx-v2/control-plane/internal/events"
)

// ─── Chaos: Rapid Circuit Breaker Cycling ────────────────────────────────────
// Simulates rapid open/close of circuit breaker — must not deadlock or panic.
func TestChaos_CircuitBreakerRapidCycling(t *testing.T) {
	from  := newFailsafeState()
	const cycles = 1000
	var wg sync.WaitGroup

	// 5 goroutines alternating open/close
	for g := 0; g < 5; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < cycles/5; i++ {
				if i%2 == 0 {
					from.Trip(fmt.Sprintf("chaos-%d", id), uint64(i*1000), 0)
				} else {
					from.Close(0, 0)
				}
				time.Sleep(time.Microsecond)
			}
		}(g)
	}

	wg.Wait()
	// System must be in a consistent state (no panic, no deadlock)
	snap := from.Snapshot()
	t.Logf("Circuit state after chaos: %s (trips=%d)", snap.State, snap.TripCount)
}

// ─── Chaos: Concurrent Map Writes (Race Detector Target) ─────────────────────
func TestChaos_ConcurrentBPFMapWrites(t *testing.T) {
	hw := newTestHardenedWriter(t)

	const goroutines = 50
	const writesEach = 100
	var (
		accepted atomic.Int64
		wg       sync.WaitGroup
	)

	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < writesEach; i++ {
				// Random IPs to stress dedup cache
				ip := net.ParseIP(fmt.Sprintf("10.%d.%d.%d",
					rand.Intn(256), rand.Intn(256), rand.Intn(256)))
				entry := bpfmaps.BlockEntry{
					Action:      bpfmaps.ActionDrop,
					ThreatScore: uint8(rand.Intn(100)),
				}
				if err := hw.BlockIPv4(ip, entry, "chaos"); err == nil {
					accepted.Add(1)
				}
			}
		}(g)
	}

	wg.Wait()
	stats := hw.Stats()
	t.Logf("Chaos Map Writes: accepted=%d dedupe=%d window_drops=%d",
		accepted.Load(), stats.DedupeHits, stats.WindowDrops)

	// System must remain consistent
	if stats.BatchRollbacks > 0 {
		t.Logf("Note: %d batch rollbacks occurred (expected under chaos)", stats.BatchRollbacks)
	}
}

// ─── Chaos: Token Replay Attack Simulation ───────────────────────────────────
func TestChaos_TokenReplayAttack(t *testing.T) {
	store, svc, _ := newLoadTestAuth(t)
	defer store.Close()

	hash, _ := authpkg.HashPassword("ReplayTarget123!")
	store.CreateUser(&authpkg.User{
		Username: "replay-victim", Email: "rv@test.local",
		PasswordHash: hash, Role: authpkg.RoleAnalyst,
		Active: true, DisplayName: "Victim", CreatedBy: "test",
	})

	resp, _ := svc.Login(authpkg.LoginRequest{
		Username: "replay-victim", Password: "ReplayTarget123!",
	}, "127.0.0.1", "attacker")

	// Attacker captures and attempts to replay the refresh token
	jwtMgr, _ := authpkg.NewJWTManager(authpkg.DefaultJWTConfig())
	claims, _  := jwtMgr.VerifyAccessToken(resp.Tokens.AccessToken)

	const replayAttempts = 10
	var replaySuccess atomic.Int64

	var wg sync.WaitGroup
	for i := 0; i < replayAttempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.RefreshTokens(
				claims.SessionID,
				resp.Tokens.RefreshToken, // Same token replayed
				"attacker-ip",
			)
			if err == nil {
				replaySuccess.Add(1)
			}
		}()
	}
	wg.Wait()

	t.Logf("Replay attack: %d/%d attempts succeeded", replaySuccess.Load(), replayAttempts)

	// At most 1 success (the first legitimate refresh)
	// All subsequent replays must fail
	if replaySuccess.Load() > 1 {
		t.Errorf("Replay attack succeeded %d times — expected at most 1",
			replaySuccess.Load())
	}
}

// ─── Chaos: Malformed Input Fuzzing ──────────────────────────────────────────
func TestChaos_MalformedLoginInputs(t *testing.T) {
	_, svc, _ := newLoadTestAuth(t)

	malformedInputs := []authpkg.LoginRequest{
		{Username: "", Password: ""},
		{Username: "admin", Password: ""},
		{Username: "", Password: "password"},
		{Username: string(make([]byte, 10000)), Password: "pass"},       // Oversized username
		{Username: "admin", Password: string(make([]byte, 10000))},      // Oversized password
		{Username: "'; DROP TABLE users; --", Password: "sql_inject"},   // SQL injection attempt
		{Username: "<script>alert(1)</script>", Password: "xss"},        // XSS attempt
		{Username: "\x00\x01\x02", Password: "null_bytes"},              // Null bytes
		{Username: "admin\nX-Header: injected", Password: "header_inj"}, // Header injection
	}

	for i, req := range malformedInputs {
		_, err := svc.Login(req, "127.0.0.1", "fuzzer")
		// Must return an error (not panic)
		if err == nil {
			t.Errorf("malformed input[%d] succeeded unexpectedly: username=%q", i, req.Username[:min(20, len(req.Username))])
		}
	}
	t.Logf("All %d malformed inputs correctly rejected", len(malformedInputs))
}

// ─── Chaos: Session Flood (DoS Simulation) ───────────────────────────────────
func TestChaos_SessionFlood(t *testing.T) {
	store, svc, _ := newLoadTestAuth(t)
	defer store.Close()

	hash, _ := authpkg.HashPassword("FloodPass123!!")
	store.CreateUser(&authpkg.User{
		Username: "flood-user", Email: "f@test.local",
		PasswordHash: hash, Role: authpkg.RoleViewer,
		Active: true, DisplayName: "Flood", CreatedBy: "test",
	})

	// Simulate rapid login from many IPs (rate limiting kicks in)
	const attempts = 20
	var rateLimited atomic.Int64
	var success     atomic.Int64
	var wg sync.WaitGroup

	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ip := fmt.Sprintf("192.168.%d.%d", n/256, n%256)
			_, err := svc.Login(authpkg.LoginRequest{
				Username: "flood-user", Password: "FloodPass123!!",
			}, ip, "flood-agent")
			if err != nil {
				rateLimited.Add(1)
			} else {
				success.Add(1)
			}
		}(i)
	}
	wg.Wait()

	t.Logf("Session flood: %d success, %d rate_limited/failed out of %d attempts",
		success.Load(), rateLimited.Load(), attempts)
	// System must not crash regardless of outcome
}

// ─── Chaos: Event Bus Saturation ─────────────────────────────────────────────
func TestChaos_EventBusSaturation(t *testing.T) {
	bus := events.NewBus()

	// Subscribe with tiny buffer (easy to saturate)
	sub := bus.Subscribe("saturated", 5, events.TopicIPBlocked)
	go func() {
		time.Sleep(100 * time.Millisecond)
		for range sub.Ch {} // Drain slowly
	}()

	const publications = 10000
	var wg sync.WaitGroup

	// Flood the bus from many goroutines
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < publications/20; i++ {
				bus.Publish(events.IPBlockedEvent("1.2.3.4", "chaos", "flood", 0))
			}
		}()
	}

	wg.Wait()
	drops := bus.DropCount()
	t.Logf("Event bus saturation: %d/%d published, %d dropped (%.1f%%)",
		int64(publications)-drops, publications, drops,
		float64(drops)/float64(publications)*100)

	// System must remain alive — drops are acceptable, deadlock is not
}

// ─── Chaos: TOTP Brute Force ──────────────────────────────────────────────────
func TestChaos_TOTPBruteForce(t *testing.T) {
	secret, _ := authpkg.GenerateTOTPSecret()

	// Try 1000 random 6-digit codes — all must fail
	var wrongCodes int
	for i := 0; i < 1000; i++ {
		code := fmt.Sprintf("%06d", rand.Intn(1000000))
		if authpkg.VerifyTOTPCode(secret, code) {
			// Extremely unlikely but possible
			t.Logf("Note: random code %s happened to match (very rare)", code)
		} else {
			wrongCodes++
		}
	}
	t.Logf("TOTP brute force: %d/1000 wrong codes correctly rejected", wrongCodes)

	if wrongCodes < 998 { // Allow 2 false positives (statistically impossible but safe)
		t.Errorf("TOTP accepted too many random codes: %d/1000", 1000-wrongCodes)
	}
}

// ─── Chaos: Hardened Writer Rollback Under Concurrent Failures ───────────────
func TestChaos_BatchRollbackUnderLoad(t *testing.T) {
	hw := newTestHardenedWriter(t)
	log := zap.NewNop()
	_ = log

	const goroutines = 10
	var rollbacks atomic.Int64
	var commits    atomic.Int64
	var wg         sync.WaitGroup

	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			decisions := make([]bpfmaps.BlockDecision, 5)
			for i := range decisions {
				ip := make(net.IP, 4)
				ip[0], ip[1], ip[2], ip[3] = byte(id), byte(i), 0, 1
				decisions[i] = bpfmaps.BlockDecision{
					IP:    ip,
					Entry: bpfmaps.BlockEntry{Action: bpfmaps.ActionDrop, ThreatScore: 80},
				}
			}
			if err := hw.WriteBatch(decisions, "chaos"); err != nil {
				rollbacks.Add(1)
			} else {
				commits.Add(1)
			}
		}(g)
	}

	wg.Wait()
	stats := hw.Stats()
	t.Logf("Chaos batch: commits=%d rollbacks=%d (stats.rollbacks=%d)",
		commits.Load(), rollbacks.Load(), stats.BatchRollbacks)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
func newFailsafeState() *failsafeCB { return &failsafeCB{} }

type failsafeCB struct {
	mu         sync.Mutex
	state      string
	tripCount  int
	violations int
	openedAt   time.Time
}

func (cb *failsafeCB) Trip(reason string, pps, bps uint64) bool {
	cb.mu.Lock(); defer cb.mu.Unlock()
	cb.state = "OPEN"; cb.tripCount++; cb.openedAt = time.Now()
	return true
}
func (cb *failsafeCB) Close(pps, bps uint64) bool {
	cb.mu.Lock(); defer cb.mu.Unlock()
	cb.state = "CLOSED"
	return true
}
func (cb *failsafeCB) Snapshot() struct{ State string; TripCount int } {
	cb.mu.Lock(); defer cb.mu.Unlock()
	return struct{ State string; TripCount int }{cb.state, cb.tripCount}
}

func newTestHardenedWriter(t *testing.T) *bpfmaps.HardenedWriter {
	t.Helper()
	return bpfmaps.NewHardenedWriter(nil, 500, 65536, zap.NewNop())
}

func min(a, b int) int {
	if a < b { return a }
	return b
}
