// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Auth service tests (control-plane/internal/auth/service_test.go).
//              Integration tests for login, refresh, logout, RBAC, and
//              account lockout behaviour.
// =============================================================================

package auth

import (
	"testing"
	"time"
)

// ─── Test Store (in-memory SQLite) ────────────────────────────────────────────
func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(":memory:", 25*time.Minute, newNopLogger())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

func newTestJWT(t *testing.T) *JWTManager {
	t.Helper()
	cfg := JWTConfig{
		PrivateKeyPath:    t.TempDir() + "/private.pem",
		PublicKeyPath:     t.TempDir() + "/public.pem",
		AccessTokenTTL:    15 * time.Minute,
		RefreshTokenTTL:   7 * 24 * time.Hour,
		InactivityTimeout: 25 * time.Minute,
		Issuer:            "falx-test",
	}
	mgr, err := NewJWTManager(cfg)
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}
	return mgr
}

func newTestService(t *testing.T) (*Service, *Store) {
	t.Helper()
	store := newTestStore(t)
	jwt   := newTestJWT(t)
	svc   := NewService(store, jwt, newNopLogger())
	return svc, store
}

// ─── User Creation Helper ─────────────────────────────────────────────────────
func createUser(t *testing.T, store *Store, username, password string, role Role) *User {
	t.Helper()
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	u := &User{
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
	return u
}

// ─── Login Tests ──────────────────────────────────────────────────────────────
func TestLogin_Success(t *testing.T) {
	svc, store := newTestService(t)
	createUser(t, store, "alice", "SecurePassword123!", RoleAnalyst)

	resp, err := svc.Login(LoginRequest{
		Username: "alice",
		Password: "SecurePassword123!",
	}, "127.0.0.1", "test-agent")

	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if resp.Tokens.AccessToken == "" {
		t.Error("access token should not be empty")
	}
	if resp.Tokens.RefreshToken == "" {
		t.Error("refresh token should not be empty")
	}
	if resp.Tokens.TokenType != "Bearer" {
		t.Errorf("token type should be Bearer, got %s", resp.Tokens.TokenType)
	}
	if resp.User.Username != "alice" {
		t.Errorf("user username mismatch: %s", resp.User.Username)
	}
	if resp.User.Role != RoleAnalyst {
		t.Errorf("user role mismatch: %s", resp.User.Role)
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	svc, store := newTestService(t)
	createUser(t, store, "bob", "CorrectPass123!", RoleViewer)

	_, err := svc.Login(LoginRequest{
		Username: "bob",
		Password: "WrongPassword123!",
	}, "127.0.0.1", "agent")

	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got: %v", err)
	}
}

func TestLogin_NonExistentUser(t *testing.T) {
	svc, _ := newTestService(t)

	_, err := svc.Login(LoginRequest{
		Username: "nobody",
		Password: "SomePassword123!",
	}, "127.0.0.1", "agent")

	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got: %v", err)
	}
}

func TestLogin_InactiveUser(t *testing.T) {
	svc, store := newTestService(t)
	u := createUser(t, store, "inactive", "Password123!!", RoleViewer)
	u.Active = false
	store.UpdateUser(u)

	_, err := svc.Login(LoginRequest{
		Username: "inactive",
		Password: "Password123!!",
	}, "127.0.0.1", "agent")

	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials for inactive user, got: %v", err)
	}
}

func TestLogin_LockedAccount(t *testing.T) {
	svc, store := newTestService(t)
	u := createUser(t, store, "locked-user", "Password1234!!", RoleViewer)
	u.Locked = true
	store.UpdateUser(u)

	_, err := svc.Login(LoginRequest{
		Username: "locked-user",
		Password: "Password1234!!",
	}, "127.0.0.1", "agent")

	if err != ErrAccountLocked {
		t.Errorf("expected ErrAccountLocked, got: %v", err)
	}
}

// ─── Account Lockout Tests ────────────────────────────────────────────────────
func TestLogin_LockoutAfterFailedAttempts(t *testing.T) {
	svc, store := newTestService(t)
	createUser(t, store, "victim", "RealPassword123!", RoleAnalyst)

	// Trigger 5 failed attempts
	for i := 0; i < 5; i++ {
		svc.Login(LoginRequest{
			Username: "victim",
			Password: "WrongPassword123!",
		}, "127.0.0.1", "agent")
	}

	// Account should now be locked
	u, _ := store.GetUserByUsername("victim")
	if !u.Locked {
		t.Error("account should be locked after 5 failed attempts")
	}

	// Even correct password should fail
	_, err := svc.Login(LoginRequest{
		Username: "victim",
		Password: "RealPassword123!",
	}, "127.0.0.1", "agent")
	if err != ErrAccountLocked {
		t.Errorf("locked account: expected ErrAccountLocked, got: %v", err)
	}
}

// ─── Token Refresh Tests ──────────────────────────────────────────────────────
func TestRefreshTokens_Success(t *testing.T) {
	svc, store := newTestService(t)
	createUser(t, store, "refresher", "Password5678!!", RoleSeniorAnalyst)

	loginResp, _ := svc.Login(LoginRequest{
		Username: "refresher",
		Password: "Password5678!!",
	}, "127.0.0.1", "agent")

	// Find session ID from JWT
	jwt  := newTestJWT(t)
	claims, err := jwt.VerifyAccessToken(loginResp.Tokens.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}

	pair, err := svc.RefreshTokens(
		claims.SessionID,
		loginResp.Tokens.RefreshToken,
		"127.0.0.1",
	)
	if err != nil {
		t.Fatalf("RefreshTokens: %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Error("new token pair must not be empty")
	}
	// New tokens must differ from old ones
	if pair.AccessToken == loginResp.Tokens.AccessToken {
		t.Error("new access token should differ from old")
	}
	if pair.RefreshToken == loginResp.Tokens.RefreshToken {
		t.Error("refresh token must rotate on use")
	}
}

func TestRefreshTokens_ReplayRejected(t *testing.T) {
	svc, store := newTestService(t)
	createUser(t, store, "replay-test", "Password9999!!", RoleAdmin)

	resp, _ := svc.Login(LoginRequest{
		Username: "replay-test",
		Password: "Password9999!!",
	}, "127.0.0.1", "agent")

	jwtMgr := newTestJWT(t)
	claims, _ := jwtMgr.VerifyAccessToken(resp.Tokens.AccessToken)

	// First refresh: OK
	svc.RefreshTokens(claims.SessionID, resp.Tokens.RefreshToken, "127.0.0.1")

	// Second refresh with same token: replay → all sessions revoked
	_, err := svc.RefreshTokens(claims.SessionID, resp.Tokens.RefreshToken, "127.0.0.1")
	if err == nil {
		t.Error("replayed refresh token should be rejected")
	}
}

// ─── Logout Tests ─────────────────────────────────────────────────────────────
func TestLogout(t *testing.T) {
	svc, store := newTestService(t)
	createUser(t, store, "logout-user", "LogoutPass123!", RoleViewer)

	resp, _ := svc.Login(LoginRequest{
		Username: "logout-user",
		Password: "LogoutPass123!",
	}, "127.0.0.1", "agent")

	jwtMgr := newTestJWT(t)
	claims, _ := jwtMgr.VerifyAccessToken(resp.Tokens.AccessToken)

	if err := svc.Logout(claims.SessionID, claims.UserID, "127.0.0.1"); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	// Session should be revoked
	_, err := store.GetSession(claims.SessionID)
	if err != ErrSessionRevoked {
		t.Errorf("after logout session should be revoked, got: %v", err)
	}
}

// ─── RBAC Tests ───────────────────────────────────────────────────────────────
func TestRBACPermissions(t *testing.T) {
	cases := []struct {
		role       Role
		perm       Permission
		wantAccess bool
	}{
		{RoleSuperAdmin,    PermUserDelete,     true},
		{RoleAdmin,         PermUserDelete,     false},
		{RoleAdmin,         PermUserCreate,     true},
		{RoleSeniorAnalyst, PermIPBlock,        true},
		{RoleSeniorAnalyst, PermUserCreate,     false},
		{RoleAnalyst,       PermIPBlockTemp,    true},
		{RoleAnalyst,       PermIPBlock,        false},
		{RoleViewer,        PermDashboardView,  true},
		{RoleViewer,        PermIPBlock,        false},
		{RoleViewer,        PermSystemConfig,   false},
	}

	for _, tc := range cases {
		u := &User{Role: tc.role}
		got := u.HasPermission(tc.perm)
		if got != tc.wantAccess {
			t.Errorf("role=%s perm=%s: want=%v got=%v",
				tc.role, tc.perm, tc.wantAccess, got)
		}
	}
}

func TestRoleHierarchy(t *testing.T) {
	cases := []struct {
		actor  Role
		target Role
		canManage bool
	}{
		{RoleSuperAdmin, RoleAdmin,         true},
		{RoleSuperAdmin, RoleSuperAdmin,    false}, // Can't manage same level
		{RoleAdmin,      RoleSeniorAnalyst, true},
		{RoleAdmin,      RoleAdmin,         false},
		{RoleSeniorAnalyst, RoleAnalyst,    true},
		{RoleAnalyst,    RoleViewer,        true},
		{RoleViewer,     RoleViewer,        false},
		{RoleViewer,     RoleAnalyst,       false},
	}

	for _, tc := range cases {
		actor := &User{Role: tc.actor}
		got   := actor.CanManageRole(tc.target)
		if got != tc.canManage {
			t.Errorf("actor=%s target=%s: want=%v got=%v",
				tc.actor, tc.target, tc.canManage, got)
		}
	}
}

// ─── Password Change Tests ────────────────────────────────────────────────────
func TestChangePassword(t *testing.T) {
	svc, store := newTestService(t)
	u := createUser(t, store, "changer", "OldPassword123!", RoleAnalyst)

	err := svc.ChangePassword(u.ID, ChangePasswordRequest{
		OldPassword: "OldPassword123!",
		NewPassword: "NewPassword456!",
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	// Old password should no longer work
	_, err = svc.Login(LoginRequest{
		Username: "changer",
		Password: "OldPassword123!",
	}, "127.0.0.1", "agent")
	if err != ErrInvalidCredentials {
		t.Error("old password should not work after change")
	}

	// New password should work
	_, err = svc.Login(LoginRequest{
		Username: "changer",
		Password: "NewPassword456!",
	}, "127.0.0.1", "agent")
	if err != nil {
		t.Errorf("new password should work: %v", err)
	}
}

func TestChangePassword_WrongOld(t *testing.T) {
	svc, store := newTestService(t)
	u := createUser(t, store, "wrongold", "Password1234!!", RoleViewer)

	err := svc.ChangePassword(u.ID, ChangePasswordRequest{
		OldPassword: "WrongOld123!",
		NewPassword: "NewPassword456!",
	}, "127.0.0.1")

	if err != ErrInvalidCredentials {
		t.Errorf("wrong old password: expected ErrInvalidCredentials, got: %v", err)
	}
}

// ─── Inactivity Timeout Tests ─────────────────────────────────────────────────
func TestInactivityTimeout(t *testing.T) {
	// Short timeout for testing
	store := newTestStore(t)

	// Override store with 1-second inactivity timeout
	store2, _ := NewStore(":memory:", 1*time.Second, newNopLogger())
	jwt   := newTestJWT(t)
	svc   := NewService(store2, jwt, newNopLogger())

	createUser(t, store2, "idle-user", "Password123!!", RoleViewer)

	resp, _ := svc.Login(LoginRequest{
		Username: "idle-user",
		Password: "Password123!!",
	}, "127.0.0.1", "agent")

	jwtMgr := newTestJWT(t)
	claims, _ := jwtMgr.VerifyAccessToken(resp.Tokens.AccessToken)

	// Wait for inactivity timeout
	time.Sleep(1100 * time.Millisecond)

	// Session should now be inactive
	_, err := store2.GetSession(claims.SessionID)
	if err != ErrInactivityTimeout {
		t.Errorf("expected ErrInactivityTimeout after idle period, got: %v", err)
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
func newNopLogger() *zap.Logger {
	return zap.NewNop()
}
