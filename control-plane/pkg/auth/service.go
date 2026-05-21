// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Authentication service (control-plane/internal/auth/service.go).
//              Business logic layer for all auth operations.
//              Coordinates: Store (persistence) + JWTManager (tokens) + Audit.
//
//              Security properties:
//                - Argon2id password hashing (memory-hard)
//                - Constant-time password comparison (timing-safe)
//                - Account lockout after 5 failed attempts
//                - Login rate limiting (10 req/min per IP)
//                - Refresh token rotation on every use (detect replay)
//                - Inactivity timeout enforced server-side (25 min)
//                - Session revocation propagates immediately (in-memory)
//                - All mutations produce audit log entries
// =============================================================================

package auth

import (
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ─── TOTP Enrollment State ────────────────────────────────────────────────────
// pendingTOTP holds a generated TOTP secret while the operator scans the QR
// code and submits the first valid confirmation code. Entries expire after
// 10 minutes to prevent stale enrollments accumulating in memory.
// backupHashes are NOT stored here — they are computed at confirm-time to
// avoid blocking BeginTOTPSetup on 8× Argon2id rounds.
type pendingTOTPEntry struct {
	secret     string
	plainCodes []string // hashed and persisted on confirm; shown once to user
	expiresAt  time.Time
}

// ─── Service ──────────────────────────────────────────────────────────────────
type Service struct {
	store   *Store
	jwt     *JWTManager
	log     *zap.Logger

	// Login rate limiter: IP → token bucket
	loginRLMu sync.Mutex
	loginRL   map[string]*loginRateLimiter

	// Pending TOTP enrollments: userID → entry (expires 10 min after begin)
	pendingTOTPMu sync.Mutex
	pendingTOTP   map[string]*pendingTOTPEntry
}

type loginRateLimiter struct {
	attempts  int
	resetAt   time.Time
}

const loginRateLimit    = 10 // per IP per minute
const loginRateWindow   = time.Minute

func NewService(store *Store, jwt *JWTManager, log *zap.Logger) *Service {
	return &Service{
		store:       store,
		jwt:         jwt,
		log:         log,
		loginRL:     make(map[string]*loginRateLimiter),
		pendingTOTP: make(map[string]*pendingTOTPEntry),
	}
}

// ─── TOTP Enrollment ──────────────────────────────────────────────────────────

// BeginTOTPSetup generates a new TOTP secret for the user and stashes it in
// memory until ConfirmTOTPSetup is called. Returns the enrollment details
// (provisioning URI, base32 secret, plaintext backup codes) for the wizard.
func (s *Service) BeginTOTPSetup(userID string) (*TOTPEnrollment, error) {
	user, err := s.store.GetUserByID(userID)
	if err != nil {
		return nil, ErrUserNotFound
	}

	enroll, err := BeginTOTPEnrollment(user.Username, string(user.Role))
	if err != nil {
		return nil, fmt.Errorf("generate TOTP enrollment: %w", err)
	}

	s.pendingTOTPMu.Lock()
	s.pendingTOTP[userID] = &pendingTOTPEntry{
		secret:     enroll.Secret,
		plainCodes: enroll.BackupCodes,
		expiresAt:  time.Now().Add(10 * time.Minute),
	}
	s.pendingTOTPMu.Unlock()

	return enroll, nil
}

// ConfirmTOTPSetup verifies that the operator can produce a valid TOTP code
// from the pending secret, then atomically enables 2FA on their account.
// Returns the plaintext backup codes for one-time display.
func (s *Service) ConfirmTOTPSetup(userID, code string) ([]string, error) {
	s.pendingTOTPMu.Lock()
	entry, ok := s.pendingTOTP[userID]
	if !ok || time.Now().After(entry.expiresAt) {
		delete(s.pendingTOTP, userID)
		s.pendingTOTPMu.Unlock()
		return nil, fmt.Errorf("no pending TOTP enrollment — call /auth/totp/begin first")
	}
	secret     := entry.secret
	plainCodes := entry.plainCodes
	s.pendingTOTPMu.Unlock()

	if !VerifyTOTPCode(secret, code) {
		return nil, fmt.Errorf("invalid TOTP code — check your authenticator app clock")
	}

	// Hash backup codes now (deferred from begin-time to avoid blocking the
	// wizard open on 8× Argon2id rounds — acceptable latency at confirm-time).
	backupHashes, err := HashBackupCodes(plainCodes)
	if err != nil {
		return nil, fmt.Errorf("hash backup codes: %w", err)
	}

	if err := s.store.UpdateTOTPSecret(userID, secret, true); err != nil {
		return nil, fmt.Errorf("save TOTP secret: %w", err)
	}
	if err := s.store.UpdateBackupCodes(userID, backupHashes); err != nil {
		s.log.Warn("TOTP enabled but backup codes not persisted", zap.Error(err))
	}

	s.pendingTOTPMu.Lock()
	delete(s.pendingTOTP, userID)
	s.pendingTOTPMu.Unlock()

	return plainCodes, nil
}

// ─── Login ────────────────────────────────────────────────────────────────────
func (s *Service) Login(req LoginRequest, ipAddr, userAgent string) (*LoginResponse, error) {
	// Rate limit by IP
	if err := s.checkLoginRate(ipAddr); err != nil {
		s.log.Warn("Login rate limited", zap.String("ip", ipAddr))
		return nil, err
	}

	// Look up user (constant-time to avoid username enumeration)
	user, err := s.store.GetUserByUsername(req.Username)
	if err != nil {
		// Always run password hash comparison to prevent timing attacks
		HashPassword("dummy-prevent-timing-attack") //nolint:errcheck
		s.auditLogin("", req.Username, ipAddr, userAgent, false, "user_not_found")
		return nil, ErrInvalidCredentials
	}

	// Check account state
	if !user.Active {
		s.auditLogin(user.ID, user.Username, ipAddr, userAgent, false, "account_inactive")
		return nil, ErrInvalidCredentials
	}
	if user.Locked {
		s.auditLogin(user.ID, user.Username, ipAddr, userAgent, false, "account_locked")
		return nil, ErrAccountLocked
	}

	// Verify password
	match, err := VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !match {
		s.store.RecordFailedLogin(user.ID) //nolint:errcheck
		s.auditLogin(user.ID, user.Username, ipAddr, userAgent, false, "wrong_password")
		return nil, ErrInvalidCredentials
	}

	// 2FA policy: enforced ONLY for the admin tier (admin, super_admin).
	// Lower-privilege roles authenticate with username+password alone.
	enforce2FA := user.Role.Requires2FA()

	// Verify TOTP whenever the account has it enabled (even for a non-admin who
	// opted in). For admins it is effectively mandatory via the scope gate below.
	if user.TOTPEnabled {
		if req.TOTPCode == "" {
			return nil, ErrTOTPRequired
		}
		if !verifyTOTP(user.TOTPSecret, req.TOTPCode) {
			s.auditLogin(user.ID, user.Username, ipAddr, userAgent, false, "invalid_totp")
			return nil, ErrInvalidCredentials
		}
	}

	// Reset failed attempts on successful auth
	s.store.ResetFailedLogin(user.ID) //nolint:errcheck

	// Create session
	rawRefresh, hashedRefresh, err := s.jwt.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	session := &Session{
		UserID:       user.ID,
		RefreshToken: hashedRefresh,
		UserAgent:    userAgent,
		IPAddress:    ipAddr,
		ExpiresAt:    time.Now().Add(s.jwt.RefreshTokenTTL()),
	}
	if err := s.store.CreateSession(session); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	// Generate access token.
	//   - Admin tier without TOTP yet → pre-auth scope forces enrollment first.
	//   - Admin tier with TOTP → verified above → full session scope.
	//   - Non-admin roles → 2FA not required → full session scope immediately,
	//     and TFA is considered satisfied so RequireTFAVerified does not block them.
	tfaVerified := user.TOTPEnabled || !enforce2FA
	scope := ScopeSession
	if enforce2FA && !user.TOTPEnabled {
		scope = ScopePreAuth
	}
	accessToken, expiry, err := s.jwt.GenerateAccessToken(user, session.ID, tfaVerified, scope)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	// Update last login
	user.LastLogin = time.Now().UTC()
	s.store.UpdateUser(user) //nolint:errcheck

	s.auditLogin(user.ID, user.Username, ipAddr, userAgent, true, "")
	s.log.Info("User logged in",
		zap.String("user", user.Username),
		zap.String("role", string(user.Role)),
		zap.String("ip", ipAddr),
	)

	return &LoginResponse{
		Tokens: TokenPair{
			AccessToken:  accessToken,
			RefreshToken: rawRefresh,
			TokenType:    "Bearer",
			ExpiresIn:    int64(s.jwt.AccessTokenTTL().Seconds()),
			ExpiresAt:    expiry,
		},
		User: UserToView(user),
	}, nil
}

// ─── Refresh ──────────────────────────────────────────────────────────────────
// RefreshTokens rotates the refresh token (single-use) and issues a new access token.
func (s *Service) RefreshTokens(
	sessionID   string,
	rawRefresh  string,
	ipAddr      string,
) (*TokenPair, error) {
	session, err := s.store.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	// Verify the raw refresh token against the stored hash
	match, err := VerifyPassword(rawRefresh, session.RefreshToken)
	if err != nil || !match {
		// Possible replay attack: revoke all sessions for this user
		s.log.Warn("Refresh token mismatch — possible replay attack",
			zap.String("session_id", sessionID),
			zap.String("ip", ipAddr),
		)
		s.store.RevokeAllUserSessions(session.UserID) //nolint:errcheck
		return nil, ErrInvalidCredentials
	}

	// Get user
	user, err := s.store.GetUserByID(session.UserID)
	if err != nil {
		return nil, err
	}
	if !user.Active || user.Locked {
		return nil, ErrInvalidCredentials
	}

	// Rotate refresh token: revoke the old session FIRST, then persist the new
	// one. This prevents a window where both old and new tokens are simultaneously
	// valid if CreateSession succeeds but RevokeSession is never reached.
	// SEC-FIX-004: OWASP A07:2021 Identification and Authentication Failures —
	// refresh token replay window eliminated by atomic revoke-before-reissue.
	if err := s.store.RevokeSession(sessionID); err != nil {
		s.log.Warn("Failed to revoke old session during rotation",
			zap.String("session_id", sessionID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("session rotation failed: %w", err)
	}

	rawNew, hashedNew, err := s.jwt.GenerateRefreshToken()
	if err != nil {
		return nil, err
	}
	session.RefreshToken = hashedNew
	session.LastActivityAt = time.Now().UTC()
	session.ExpiresAt = time.Now().Add(s.jwt.RefreshTokenTTL())
	if err := s.store.CreateSession(session); err != nil {
		return nil, fmt.Errorf("create rotated session: %w", err)
	}

	// Generate new access token. Preserve the same TFA/scope policy as login:
	// 2FA is enforced only for the admin tier. Non-admin roles keep full session
	// scope with TFA considered satisfied (password-only accounts).
	enforce2FA := user.Role.Requires2FA()
	tfaOK := user.TOTPEnabled || !enforce2FA
	refreshScope := ScopeSession
	if enforce2FA && !user.TOTPEnabled {
		refreshScope = ScopePreAuth
	}
	accessToken, expiry, err := s.jwt.GenerateAccessToken(user, session.ID, tfaOK, refreshScope)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: rawNew,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.jwt.AccessTokenTTL().Seconds()),
		ExpiresAt:    expiry,
	}, nil
}

// ─── Logout ───────────────────────────────────────────────────────────────────
func (s *Service) Logout(sessionID, userID, ipAddr string) error {
	if err := s.store.RevokeSession(sessionID); err != nil {
		return err
	}
	s.store.WriteAuditEvent(AuthAuditEvent{
		UserID:    userID,
		Action:    "logout",
		IPAddress: ipAddr,
		Success:   true,
	})
	return nil
}

// LogoutAll revokes all sessions for a user (used after password change).
func (s *Service) LogoutAll(userID, ipAddr string) error {
	err := s.store.RevokeAllUserSessions(userID)
	s.store.WriteAuditEvent(AuthAuditEvent{
		UserID:    userID,
		Action:    "logout_all",
		IPAddress: ipAddr,
		Success:   err == nil,
	})
	return err
}

// ─── Register ─────────────────────────────────────────────────────────────────
// Register creates a new user. Only admins can create users; enforced at middleware.
func (s *Service) Register(req RegisterRequest, actorID, actorIP string) (*UserView, error) {
	// Password strength
	if err := ValidatePasswordStrength(req.Password); err != nil {
		return nil, err
	}

	// Get actor to validate they can assign this role
	actor, err := s.store.GetUserByID(actorID)
	if err != nil {
		return nil, err
	}
	if !actor.CanManageRole(req.Role) {
		return nil, fmt.Errorf("insufficient privileges to assign role %s", req.Role)
	}

	hash, err := HashPassword(req.Password)
	if err != nil {
		return nil, err
	}

	user := &User{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: hash,
		Role:         req.Role,
		Active:       true,
		DisplayName:  req.DisplayName,
		CreatedBy:    actorID,
	}

	if err := s.store.CreateUser(user); err != nil {
		return nil, err
	}

	s.store.WriteAuditEvent(AuthAuditEvent{
		UserID:    actorID,
		Action:    "user_create",
		Resource:  user.ID,
		IPAddress: actorIP,
		Success:   true,
		Metadata:  map[string]string{"new_user": user.Username, "role": string(req.Role)},
	})

	s.log.Info("User created",
		zap.String("username", user.Username),
		zap.String("role", string(user.Role)),
		zap.String("by", actorID),
	)

	view := UserToView(user)
	return &view, nil
}

// ─── Change Password ──────────────────────────────────────────────────────────
func (s *Service) ChangePassword(userID string, req ChangePasswordRequest, ip string) error {
	user, err := s.store.GetUserByID(userID)
	if err != nil {
		return err
	}

	match, err := VerifyPassword(req.OldPassword, user.PasswordHash)
	if err != nil || !match {
		return ErrInvalidCredentials
	}

	if err := ValidatePasswordStrength(req.NewPassword); err != nil {
		return err
	}

	hash, err := HashPassword(req.NewPassword)
	if err != nil {
		return err
	}

	if err := s.store.UpdatePasswordHash(userID, hash); err != nil {
		return err
	}

	// Revoke all existing sessions (force re-login)
	s.store.RevokeAllUserSessions(userID) //nolint:errcheck

	s.store.WriteAuditEvent(AuthAuditEvent{
		UserID:    userID,
		Action:    "password_change",
		IPAddress: ip,
		Success:   true,
	})
	return nil
}

// ─── Validate Token + Touch Session ──────────────────────────────────────────
// ValidateRequest is called by the auth middleware on every API request.
func (s *Service) ValidateRequest(tokenStr string) (*TokenClaims, error) {
	claims, err := s.jwt.VerifyAccessToken(tokenStr)
	if err != nil {
		return nil, err
	}

	// Validate session (checks inactivity timeout)
	if _, err := s.store.GetSession(claims.SessionID); err != nil {
		return nil, err
	}

	// Slide inactivity window
	s.store.TouchSession(claims.SessionID) //nolint:errcheck

	return claims, nil
}

// ─── IssueUpgradedToken ───────────────────────────────────────────────────────
// IssueUpgradedToken reissues an access token with tfa_ok=true and scope=session
// for the given user+session. Called by TOTPConfirm after the first valid code
// confirms enrollment, so the frontend can transition to the dashboard without
// a full re-login.
func (s *Service) IssueUpgradedToken(userID, sessionID string) (*TokenPair, error) {
	user, err := s.store.GetUserByID(userID)
	if err != nil {
		return nil, err
	}
	accessToken, expiry, err := s.jwt.GenerateAccessToken(user, sessionID, true, ScopeSession)
	if err != nil {
		return nil, fmt.Errorf("issue upgraded token: %w", err)
	}
	return &TokenPair{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.jwt.AccessTokenTTL().Seconds()),
		ExpiresAt:   expiry,
	}, nil
}

// ─── DisableTOTPSetup ─────────────────────────────────────────────────────────
// DisableTOTPSetup clears TOTP for targetUserID and revokes all their sessions.
// Intended for super_admin use during debugging or account recovery.
func (s *Service) DisableTOTPSetup(targetUserID, actorUserID, actorIP string) error {
	if _, err := s.store.GetUserByID(targetUserID); err != nil {
		return ErrUserNotFound
	}
	if err := s.store.DisableTOTP(targetUserID); err != nil {
		return fmt.Errorf("disable TOTP: %w", err)
	}
	s.store.RevokeAllUserSessions(targetUserID) //nolint:errcheck
	s.store.WriteAuditEvent(AuthAuditEvent{
		UserID:    actorUserID,
		Action:    "totp_disable",
		Resource:  targetUserID,
		IPAddress: actorIP,
		Success:   true,
	})
	return nil
}

// ─── Login Rate Limiter ───────────────────────────────────────────────────────
func (s *Service) checkLoginRate(ipAddr string) error {
	ip, _, _ := net.SplitHostPort(ipAddr)
	if ip == "" {
		ip = ipAddr
	}

	s.loginRLMu.Lock()
	defer s.loginRLMu.Unlock()

	now := time.Now()

	// Evict expired entries to prevent unbounded memory growth under sustained
	// multi-IP attacks. O(n) but only runs on the slow auth path.
	for k, v := range s.loginRL {
		if now.After(v.resetAt) {
			delete(s.loginRL, k)
		}
	}

	rl, ok := s.loginRL[ip]
	if !ok || now.After(rl.resetAt) {
		s.loginRL[ip] = &loginRateLimiter{attempts: 1, resetAt: now.Add(loginRateWindow)}
		return nil
	}

	rl.attempts++
	if rl.attempts > loginRateLimit {
		return fmt.Errorf("too many login attempts — try again in %s",
			rl.resetAt.Sub(now).Round(time.Second))
	}
	return nil
}

// ─── Audit Helpers ────────────────────────────────────────────────────────────
func (s *Service) auditLogin(userID, username, ip, ua string, success bool, reason string) {
	s.store.WriteAuditEvent(AuthAuditEvent{
		UserID:     userID,
		Username:   username,
		Action:     "login",
		IPAddress:  ip,
		UserAgent:  ua,
		Success:    success,
		FailReason: reason,
	})
}

// verifyTOTP delegates to the full RFC 6238 implementation in totp.go.
func verifyTOTP(secret, code string) bool {
	return VerifyTOTPCode(secret, code)
}
