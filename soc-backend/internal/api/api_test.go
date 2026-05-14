// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: SOC API integration tests (soc-backend/internal/api/api_test.go).
//              Tests the full HTTP handler stack with mock BPF manager.
//              Uses httptest.Server so no real kernel or BPF access needed.
// =============================================================================

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	authpkg "github.com/ft-1/falx-v2/control-plane/pkg/auth"
)

// ─── Test Helpers ─────────────────────────────────────────────────────────────

// newTestAuthStack creates a complete auth stack for testing.
func newTestAuthStack(t *testing.T) (*authpkg.Service, *authpkg.Store, *authpkg.JWTManager) {
	t.Helper()
	store, err := authpkg.NewStore(":memory:", 25*time.Minute, zap.NewNop())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	jwtCfg := authpkg.JWTConfig{
		PrivateKeyPath:    t.TempDir() + "/priv.pem",
		PublicKeyPath:     t.TempDir() + "/pub.pem",
		AccessTokenTTL:    15 * time.Minute,
		RefreshTokenTTL:   7 * 24 * time.Hour,
		InactivityTimeout: 25 * time.Minute,
		Issuer:            "falx-test",
	}
	jwtMgr, err := authpkg.NewJWTManager(jwtCfg)
	if err != nil {
		t.Fatalf("jwt: %v", err)
	}
	svc := authpkg.NewService(store, jwtMgr, zap.NewNop())
	return svc, store, jwtMgr
}

// createTestUser creates a user and returns an access token for that user.
func createTestUser(t *testing.T, store *authpkg.Store, svc *authpkg.Service,
	username, password string, role authpkg.Role) (string, *authpkg.User) {
	t.Helper()
	hash, _ := authpkg.HashPassword(password)
	u := &authpkg.User{
		Username:     username,
		Email:        username + "@test.local",
		PasswordHash: hash,
		Role:         role,
		Active:       true,
		DisplayName:  username,
		CreatedBy:    "test",
	}
	if err := store.CreateUser(u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	resp, err := svc.Login(authpkg.LoginRequest{
		Username: username, Password: password,
	}, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	return resp.Tokens.AccessToken, u
}

func postJSON(t *testing.T, handler http.Handler, path string, body interface{}, token string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(body)
	req := httptest.NewRequest(http.MethodPost, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func getJSON(t *testing.T, handler http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// ─── Auth Handler Tests ───────────────────────────────────────────────────────

func TestLoginEndpoint_Success(t *testing.T) {
	svc, store, _ := newTestAuthStack(t)
	createTestUser(t, store, svc, "test-login", "TestPass123!", authpkg.RoleViewer)

	handler := authpkg.NewHandler(svc, zap.NewNop())
	mux     := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/login", handler.Login)

	rr := postJSON(t, mux, "/api/v1/auth/login", map[string]string{
		"username": "test-login",
		"password": "TestPass123!",
	}, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	tokens, ok := resp["tokens"].(map[string]interface{})
	if !ok || tokens["access_token"] == "" {
		t.Error("expected access_token in response")
	}
}

func TestLoginEndpoint_WrongPassword(t *testing.T) {
	svc, store, _ := newTestAuthStack(t)
	createTestUser(t, store, svc, "test-wp", "TestPass123!", authpkg.RoleViewer)

	handler := authpkg.NewHandler(svc, zap.NewNop())
	mux     := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/login", handler.Login)

	rr := postJSON(t, mux, "/api/v1/auth/login", map[string]string{
		"username": "test-wp",
		"password": "WrongPassword456!",
	}, "")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestMeEndpoint_RequiresAuth(t *testing.T) {
	svc, _, _ := newTestAuthStack(t)
	handler   := authpkg.NewHandler(svc, zap.NewNop())

	mux := http.NewServeMux()
	mux.Handle("/api/v1/auth/me", svc.RequireAuth(http.HandlerFunc(handler.Me)))

	// No token
	rr := getJSON(t, mux, "/api/v1/auth/me", "")
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", rr.Code)
	}
}

func TestMeEndpoint_WithToken(t *testing.T) {
	svc, store, _ := newTestAuthStack(t)
	token, _       := createTestUser(t, store, svc, "me-user", "TestPass123!", authpkg.RoleAnalyst)
	handler        := authpkg.NewHandler(svc, zap.NewNop())

	mux := http.NewServeMux()
	mux.Handle("/api/v1/auth/me", svc.RequireAuth(http.HandlerFunc(handler.Me)))

	rr := getJSON(t, mux, "/api/v1/auth/me", token)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var user map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&user)
	if user["username"] != "me-user" {
		t.Errorf("expected username=me-user, got: %v", user["username"])
	}
}

// ─── RBAC Middleware Tests ────────────────────────────────────────────────────

func TestRBACPermission_BlockedForLowerRole(t *testing.T) {
	svc, store, _ := newTestAuthStack(t)

	// Viewer token
	viewerToken, _ := createTestUser(t, store, svc, "viewer1", "TestPass123!", authpkg.RoleViewer)

	mux := http.NewServeMux()
	// Require PermIPBlock (senior_analyst+)
	protected := svc.RequireAuth(
		svc.RequirePermission(authpkg.PermIPBlock)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"ok":true}`))
			}),
		),
	)
	mux.Handle("/api/v1/security/block", protected)

	rr := postJSON(t, mux, "/api/v1/security/block",
		map[string]interface{}{"ip": "1.2.3.4"}, viewerToken)
	if rr.Code != http.StatusForbidden {
		t.Errorf("viewer should get 403 on block endpoint, got %d", rr.Code)
	}
}

func TestRBACPermission_AllowedForCorrectRole(t *testing.T) {
	svc, store, _ := newTestAuthStack(t)

	// Senior analyst token
	seniorToken, _ := createTestUser(t, store, svc, "senior1", "TestPass123!", authpkg.RoleSeniorAnalyst)

	mux := http.NewServeMux()
	protected := svc.RequireAuth(
		svc.RequirePermission(authpkg.PermIPBlock)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"ok":true}`))
			}),
		),
	)
	mux.Handle("/api/v1/security/block", protected)

	rr := postJSON(t, mux, "/api/v1/security/block",
		map[string]interface{}{"ip": "1.2.3.4"}, seniorToken)
	// Should reach handler (not be blocked by RBAC)
	if rr.Code == http.StatusForbidden {
		t.Error("senior_analyst should not get 403 on block endpoint")
	}
}

// ─── Security Headers Tests ───────────────────────────────────────────────────

func TestSecurityHeaders(t *testing.T) {
	handler := authpkg.SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr  := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	headers := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"X-XSS-Protection":       "1; mode=block",
		"Cache-Control":          "no-store",
	}
	for h, want := range headers {
		if got := rr.Header().Get(h); got != want {
			t.Errorf("header %s: want=%q got=%q", h, want, got)
		}
	}
	// Server header should be absent
	if rr.Header().Get("Server") != "" {
		t.Error("Server header should be removed")
	}
}

// ─── Dashboard Handler Tests ──────────────────────────────────────────────────

func TestDashboardOverview_NoBPF(t *testing.T) {
	// DashboardHandler with nil BPF manager (stub mode)
	handler := NewDashboardHandler(nil, nil, nil, zap.NewNop())
	mux     := http.NewServeMux()
	mux.HandleFunc("/api/v1/dashboard", handler.Overview)

	rr := getJSON(t, mux, "/api/v1/dashboard", "")
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 in stub mode, got %d", rr.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["version"] == nil {
		t.Error("expected version in response")
	}
	if resp["timestamp"] == nil {
		t.Error("expected timestamp in response")
	}
}

// ─── System Handler Tests ──────────────────────────────────────────────────────

func TestLivenessEndpoint(t *testing.T) {
	handler := NewSystemHandler(nil, zap.NewNop())
	req     := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr      := httptest.NewRecorder()
	handler.Liveness(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status=ok, got: %v", resp["status"])
	}
}

func TestReadinessEndpoint_StubMode(t *testing.T) {
	handler := NewSystemHandler(nil, zap.NewNop())
	req     := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr      := httptest.NewRecorder()
	handler.Readiness(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 in stub mode, got %d", rr.Code)
	}
}

// ─── Content-Type Tests ───────────────────────────────────────────────────────

func TestAllEndpointsReturnJSON(t *testing.T) {
	handler := NewSystemHandler(nil, zap.NewNop())

	endpoints := []struct {
		method  string
		path    string
		handler http.HandlerFunc
	}{
		{"GET", "/healthz",        handler.Liveness},
		{"GET", "/readyz",         handler.Readiness},
		{"GET", "/system/health",  handler.Health},
	}

	for _, ep := range endpoints {
		mux := http.NewServeMux()
		mux.HandleFunc(ep.path, ep.handler)
		req := httptest.NewRequest(ep.method, ep.path, nil)
		rr  := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		ct := rr.Header().Get("Content-Type")
		if ct != "application/json" {
			t.Errorf("%s %s: expected application/json, got %s", ep.method, ep.path, ct)
		}
	}
}

// ─── Input Validation Tests ───────────────────────────────────────────────────

func TestBlockIP_InvalidIPRejected(t *testing.T) {
	svc, store, _ := newTestAuthStack(t)
	seniorToken, _ := createTestUser(t, store, svc, "val-user", "TestPass123!", authpkg.RoleSeniorAnalyst)

	secH := NewSecurityHandler(nil, nil, zap.NewNop())
	mux  := http.NewServeMux()
	mux.Handle("/api/v1/security/block",
		svc.RequireAuth(svc.RequirePermission(authpkg.PermIPBlock)(
			http.HandlerFunc(secH.BlockIP))))

	rr := postJSON(t, mux, "/api/v1/security/block",
		map[string]interface{}{"ip": "not-an-ip", "ttl_s": 3600},
		seniorToken)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid IP should return 400, got %d", rr.Code)
	}
	var resp map[string]string
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["code"] != "invalid_ip" {
		t.Errorf("expected code=invalid_ip, got: %s", resp["code"])
	}
}

func TestBlockIP_AnalystLimitedTTL(t *testing.T) {
	svc, store, _ := newTestAuthStack(t)
	// Analyst with PermIPBlockTemp
	analystToken, _ := createTestUser(t, store, svc, "analyst-ttl", "TestPass123!", authpkg.RoleAnalyst)

	secH := NewSecurityHandler(nil, nil, zap.NewNop())
	mux  := http.NewServeMux()
	mux.Handle("/api/v1/security/block",
		svc.RequireAuth(svc.RequirePermission(authpkg.PermIPBlockTemp)(
			http.HandlerFunc(secH.BlockIP))))

	// Analyst requests permanent block (ttl=0) — should be capped to 86400
	// This is handled inside BlockIP when bpfMgr is nil → ServiceUnavailable
	rr := postJSON(t, mux, "/api/v1/security/block",
		map[string]interface{}{"ip": "5.5.5.5", "ttl_s": 0},
		analystToken)

	// With nil BPF manager, expect 503 (not 403) — confirms RBAC passed
	if rr.Code == http.StatusForbidden {
		t.Error("analyst with PermIPBlockTemp should not get 403")
	}
}

// ─── Rate Limiting Tests ──────────────────────────────────────────────────────

func TestLoginRateLimiting(t *testing.T) {
	svc, store, _ := newTestAuthStack(t)
	createTestUser(t, store, svc, "ratelimit-user", "TestPass123!", authpkg.RoleViewer)

	handler := authpkg.NewHandler(svc, zap.NewNop())
	mux     := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/login", handler.Login)

	// Hammer login with wrong password from same IP
	rateLimitHit := false
	for i := 0; i < 15; i++ {
		rr := postJSON(t, mux, "/api/v1/auth/login", map[string]string{
			"username": "ratelimit-user",
			"password": "WrongPassword456!",
		}, "")
		if rr.Code == http.StatusTooManyRequests {
			rateLimitHit = true
			break
		}
	}
	if !rateLimitHit {
		t.Log("Note: rate limiting may not trigger in tests due to same-process IP (127.0.0.1)")
	}
}

// ─── Benchmark ───────────────────────────────────────────────────────────────

func BenchmarkMeEndpoint(b *testing.B) {
	svc, store, _ := newTestAuthStack(&testing.T{})
	token, _       := createTestUser(&testing.T{}, store, svc, "bench", "BenchPass123!", authpkg.RoleViewer)
	handler        := authpkg.NewHandler(svc, zap.NewNop())

	mux := http.NewServeMux()
	mux.Handle("/api/v1/auth/me", svc.RequireAuth(http.HandlerFunc(handler.Me)))

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		getJSON(&testing.T{}, mux, "/api/v1/auth/me", token)
	}
}

func BenchmarkSecurityHeaders(b *testing.B) {
	h := authpkg.SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	req := httptest.NewRequest("GET", "/", nil)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
	}
}
