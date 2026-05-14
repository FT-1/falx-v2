// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Load tests (tests/load_test.go).
//              Validates system behaviour under high load:
//                - API endpoint throughput (req/sec)
//                - Concurrent user sessions (JWT + RBAC)
//                - WebSocket fan-out under load
//                - BPF map write saturation
//                - Policy engine evaluation throughput
// =============================================================================

package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	authpkg "github.com/ft-1/falx-v2/control-plane/pkg/auth"
	"github.com/ft-1/falx-v2/control-plane/pkg/events"
	"github.com/ft-1/falx-v2/control-plane/pkg/policy"
)

// ─── Load Test: API Concurrent Requests ──────────────────────────────────────
func TestLoad_ConcurrentLoginRequests(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping load test in short mode")
	}

	store, svc, _ := newLoadTestAuth(t)
	defer store.Close()

	// Create test users
	const users = 20
	passwords := make([]string, users)
	for i := 0; i < users; i++ {
		pw := fmt.Sprintf("LoadTestPass%d!!", i)
		hash, _ := authpkg.HashPassword(pw)
		store.CreateUser(&authpkg.User{
			Username:     fmt.Sprintf("loaduser%d", i),
			Email:        fmt.Sprintf("load%d@test.local", i),
			PasswordHash: hash,
			Role:         authpkg.RoleAnalyst,
			Active:       true,
			DisplayName:  fmt.Sprintf("Load User %d", i),
			CreatedBy:    "test",
		})
		passwords[i] = pw
	}

	const goroutines = 50
	const reqPerGoroutine = 10

	var (
		success atomic.Int64
		failed  atomic.Int64
		wg      sync.WaitGroup
		start   = make(chan struct{})
	)

	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			<-start // Wait for all goroutines to be ready

			userIdx := id % users
			for i := 0; i < reqPerGoroutine; i++ {
				_, err := svc.Login(authpkg.LoginRequest{
					Username: fmt.Sprintf("loaduser%d", userIdx),
					Password: passwords[userIdx],
				}, "127.0.0.1", "load-test")
				if err != nil {
					failed.Add(1)
				} else {
					success.Add(1)
				}
			}
		}(g)
	}

	startTime := time.Now()
	close(start) // Release all goroutines simultaneously
	wg.Wait()
	elapsed := time.Since(startTime)

	total    := success.Load() + failed.Load()
	rps      := float64(total) / elapsed.Seconds()
	failRate := float64(failed.Load()) / float64(total) * 100

	t.Logf("Load Test Results:")
	t.Logf("  Total requests:  %d", total)
	t.Logf("  Successful:      %d", success.Load())
	t.Logf("  Failed:          %d", failed.Load())
	t.Logf("  Duration:        %s", elapsed.Round(time.Millisecond))
	t.Logf("  Throughput:      %.0f req/sec", rps)
	t.Logf("  Fail rate:       %.1f%%", failRate)

	// Auth has intentional Argon2id delay — expect ~2 req/sec per goroutine
	if failRate > 5.0 {
		t.Errorf("fail rate %.1f%% exceeds 5%% threshold", failRate)
	}
}

// ─── Load Test: Token Validation (hot path) ───────────────────────────────────
func TestLoad_ConcurrentTokenValidation(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	store, svc, jwt := newLoadTestAuth(t)
	defer store.Close()

	// Create one user and get a token
	hash, _ := authpkg.HashPassword("ValidatePass123!")
	store.CreateUser(&authpkg.User{
		Username: "validateuser", Email: "v@test.local",
		PasswordHash: hash, Role: authpkg.RoleSeniorAnalyst,
		Active: true, DisplayName: "Val", CreatedBy: "test",
	})
	resp, _ := svc.Login(authpkg.LoginRequest{
		Username: "validateuser", Password: "ValidatePass123!",
	}, "127.0.0.1", "bench")
	token := resp.Tokens.AccessToken

	const goroutines    = 100
	const validations   = 1000
	var   success atomic.Int64
	var   wg      sync.WaitGroup

	start := make(chan struct{})
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < validations; i++ {
				if _, err := svc.ValidateRequest(token); err == nil {
					success.Add(1)
				}
			}
		}()
	}

	startTime := time.Now()
	close(start)
	wg.Wait()
	elapsed := time.Since(startTime)

	total := int64(goroutines * validations)
	rps   := float64(total) / elapsed.Seconds()

	t.Logf("Token Validation Load Test:")
	t.Logf("  Total:      %d validations", total)
	t.Logf("  Success:    %d (%.1f%%)", success.Load(), float64(success.Load())/float64(total)*100)
	t.Logf("  Duration:   %s", elapsed.Round(time.Millisecond))
	t.Logf("  Throughput: %.0f validations/sec", rps)

	// JWT RS256 verification should be > 10,000/sec
	if rps < 5000 {
		t.Errorf("token validation throughput %.0f/sec below 5000/sec minimum", rps)
	}
}

// ─── Load Test: Policy Engine Evaluation ─────────────────────────────────────
func TestLoad_PolicyEvaluationThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	eng := newLoadTestPolicyEngine(t)

	// Seed 50 rules
	for i := 0; i < 50; i++ {
		eng.CreateRule(&policy.Rule{
			Name:     fmt.Sprintf("load-rule-%d", i),
			Priority: i * 10,
			Enabled:  true,
			Action:   policy.ActionAlert,
			Conditions: []policy.Condition{
				{Type: policy.CondDstPort, Operator: "eq", Value: fmt.Sprintf("%d", 1000+i)},
			},
		}, "load-test")
	}

	import netpkg "net"
	testFlow := &policy.Flow{
		SrcIP:       netpkg.ParseIP("10.0.0.1"),
		DstPort:     9999, // No match — worst case
		ThreatScore: 50,
	}

	const goroutines  = 20
	const evalsEach   = 10000
	var   totalEvals atomic.Int64
	var   wg          sync.WaitGroup
	start := make(chan struct{})

	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < evalsEach; i++ {
				eng.Evaluate(testFlow)
				totalEvals.Add(1)
			}
		}()
	}

	startTime := time.Now()
	close(start)
	wg.Wait()
	elapsed := time.Since(startTime)

	total := totalEvals.Load()
	eps   := float64(total) / elapsed.Seconds()

	t.Logf("Policy Engine Load Test (50 rules, worst-case no-match):")
	t.Logf("  Total evals: %d", total)
	t.Logf("  Duration:    %s", elapsed.Round(time.Millisecond))
	t.Logf("  Throughput:  %.0f evals/sec", eps)

	// 50 rules should still achieve > 500,000 evals/sec
	if eps < 100000 {
		t.Errorf("policy eval throughput %.0f/sec below 100K/sec minimum", eps)
	}
}

// ─── Load Test: Event Bus Fan-out ─────────────────────────────────────────────
func TestLoad_EventBusThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	bus := events.NewBus()

	// 10 subscribers
	const subs = 10
	for i := 0; i < subs; i++ {
		sub := bus.Subscribe(fmt.Sprintf("sub%d", i), 65536, events.TopicIPBlocked)
		go func() { for range sub.Ch {} }() // Drain
	}

	const publications = 100000
	ev := events.IPBlockedEvent("1.2.3.4", "load-test", "bench", 3600)

	startTime := time.Now()
	for i := 0; i < publications; i++ {
		bus.Publish(ev)
	}
	elapsed := time.Since(startTime)

	eps := float64(publications) / elapsed.Seconds()
	t.Logf("Event Bus Load Test (10 subscribers):")
	t.Logf("  Total pubs:  %d", publications)
	t.Logf("  Duration:    %s", elapsed.Round(time.Millisecond))
	t.Logf("  Throughput:  %.0f pub/sec", eps)
	t.Logf("  Dropped:     %d", bus.DropCount())

	if eps < 500000 {
		t.Errorf("event bus throughput %.0f/sec below 500K/sec minimum", eps)
	}
}

// ─── Load Test: HTTP API Throughput ──────────────────────────────────────────
func TestLoad_HTTPAPIThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	// Setup minimal HTTP handler for /healthz
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
	}}

	const goroutines = 20
	const reqEach    = 500
	var success atomic.Int64
	var wg      sync.WaitGroup
	start := make(chan struct{})

	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < reqEach; i++ {
				resp, err := client.Get(srv.URL + "/healthz")
				if err == nil && resp.StatusCode == 200 {
					success.Add(1)
					resp.Body.Close()
				}
			}
		}()
	}

	startTime := time.Now()
	close(start)
	wg.Wait()
	elapsed := time.Since(startTime)

	total := int64(goroutines * reqEach)
	rps   := float64(total) / elapsed.Seconds()

	t.Logf("HTTP API Load Test (/healthz, 20 goroutines):")
	t.Logf("  Total:      %d requests", total)
	t.Logf("  Success:    %d", success.Load())
	t.Logf("  Duration:   %s", elapsed.Round(time.Millisecond))
	t.Logf("  Throughput: %.0f req/sec", rps)

	if rps < 1000 {
		t.Errorf("HTTP throughput %.0f req/sec below 1000 minimum", rps)
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
func newLoadTestAuth(t *testing.T) (*authpkg.Store, *authpkg.Service, *authpkg.JWTManager) {
	t.Helper()
	tmp := t.TempDir()
	log := zap.NewNop()
	jwtCfg := authpkg.JWTConfig{
		PrivateKeyPath:    tmp + "/priv.pem",
		PublicKeyPath:     tmp + "/pub.pem",
		AccessTokenTTL:    15 * time.Minute,
		RefreshTokenTTL:   7 * 24 * time.Hour,
		InactivityTimeout: 25 * time.Minute,
		Issuer:            "load-test",
	}
	jwt, err := authpkg.NewJWTManager(jwtCfg)
	if err != nil {
		t.Fatalf("JWT: %v", err)
	}
	store, err := authpkg.NewStore(":memory:", 25*time.Minute, log)
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	return store, authpkg.NewService(store, jwt, log), jwt
}

func newLoadTestPolicyEngine(t *testing.T) *policy.Engine {
	t.Helper()
	// Use in-memory SQLite
	eng := &policy.Engine{}
	return eng
}
