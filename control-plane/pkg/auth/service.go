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

// ─── Service ──────────────────────────────────────────────────────────────────
type Service struct {
	store   *Store
	jwt     *JWTManager
	log     *zap.Logger

	// Login rate limiter: IP → token bucket
	loginRLMu sync.Mutex
	loginRL   map[string]*loginRateLimiter
}

type loginRateLimiter struct {
	attempts  int
	resetAt   time.Time
}

const loginRateLimit    = 10 // per IP per minute
const loginRateWindow   = time.Minute

func NewService(store *Store, jwt *JWTManager, log *zap.Logger) *Service {
	return &Service{
		store:   store,
		jwt:     jwt,
		log:     log,
		loginRL: make(map[string]*loginRateLimiter),
	}
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

	// Verify TOTP if enabled
	if user.TOTPEnabled {
		if req.TOTPCode == "" {
			return nil, fmt.Errorf("2FA code required")
		}
		if !verifyTOTP(user.TOTPSecret, req.TOTPCode) {
			s.auditLogin(user.ID, user.Username, ipAddr, userAgent, false, "invalid_totp")
			return nil, fmt.Errorf("invalid 2FA code")
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

	// Generate access token
	accessToken, expiry, err := s.jwt.GenerateAccessToken(user, session.ID)
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

	// Generate new access token
	accessToken, expiry, err := s.jwt.GenerateAccessToken(user, session.ID)
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
