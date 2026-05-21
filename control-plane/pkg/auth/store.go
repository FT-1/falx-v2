// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: User and Session store (control-plane/internal/auth/store.go).
//              Thread-safe in-memory store backed by SQLite for persistence.
//              In-memory layer provides O(1) lookups on hot path.
//              SQLite provides durability across daemon restarts.
//
//              SQLite chosen over PostgreSQL for:
//                - Zero external dependencies (embedded)
//                - Sufficient for enterprise user counts (<10,000 users)
//                - File-based backup/migration
//                - WAL mode for concurrent reads
// =============================================================================

package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
)

// ─── Errors ───────────────────────────────────────────────────────────────────
var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUserExists        = errors.New("username or email already exists")
	ErrSessionNotFound   = errors.New("session not found")
	ErrSessionExpired    = errors.New("session expired")
	ErrSessionRevoked    = errors.New("session revoked")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountLocked     = errors.New("account locked — contact administrator")
	ErrInactivityTimeout = errors.New("session expired due to inactivity")
	// ErrTOTPRequired is returned by Login when the user has 2FA enabled but
	// did not supply a code. The frontend must re-prompt with the TOTP field.
	ErrTOTPRequired      = errors.New("2FA code required")
)

// ─── Store ────────────────────────────────────────────────────────────────────
type Store struct {
	db  *sql.DB
	log *zap.Logger

	// In-memory caches
	usersMu  sync.RWMutex
	users    map[string]*User   // id → user
	byName   map[string]string  // username → id
	byEmail  map[string]string  // email → id

	sessionsMu sync.RWMutex
	sessions   map[string]*Session // session_id → session

	inactivityTimeout time.Duration
}

// ─── Constructor ──────────────────────────────────────────────────────────────
func NewStore(dbPath string, inactivityTimeout time.Duration, log *zap.Logger) (*Store, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open DB: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite: single writer
	db.SetMaxIdleConns(1)

	s := &Store{
		db:                db,
		log:               log,
		users:             make(map[string]*User),
		byName:            make(map[string]string),
		byEmail:           make(map[string]string),
		sessions:          make(map[string]*Session),
		inactivityTimeout: inactivityTimeout,
	}

	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("DB migration: %w", err)
	}
	if err := s.loadCache(); err != nil {
		return nil, fmt.Errorf("cache load: %w", err)
	}

	// Ensure at least one super_admin exists
	s.ensureDefaultAdmin()

	log.Info("Auth store ready",
		zap.String("db", dbPath),
		zap.Int("users", len(s.users)),
		zap.Int("sessions", len(s.sessions)),
	)
	return s, nil
}

// ─── Schema Migration ─────────────────────────────────────────────────────────
func (s *Store) migrate() error {
	schema := `
CREATE TABLE IF NOT EXISTS users (
    id               TEXT PRIMARY KEY,
    username         TEXT UNIQUE NOT NULL,
    email            TEXT UNIQUE NOT NULL,
    password_hash    TEXT NOT NULL,
    role             TEXT NOT NULL DEFAULT 'viewer',
    active           INTEGER NOT NULL DEFAULT 1,
    locked           INTEGER NOT NULL DEFAULT 0,
    failed_attempts  INTEGER NOT NULL DEFAULT 0,
    display_name     TEXT NOT NULL DEFAULT '',
    totp_secret      TEXT NOT NULL DEFAULT '',
    totp_enabled     INTEGER NOT NULL DEFAULT 0,
    last_login       DATETIME,
    created_at       DATETIME NOT NULL,
    updated_at       DATETIME NOT NULL,
    created_by       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS sessions (
    id                TEXT PRIMARY KEY,
    user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash TEXT NOT NULL,
    user_agent        TEXT NOT NULL DEFAULT '',
    ip_address        TEXT NOT NULL DEFAULT '',
    created_at        DATETIME NOT NULL,
    last_activity_at  DATETIME NOT NULL,
    expires_at        DATETIME NOT NULL,
    revoked           INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS auth_audit (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL DEFAULT '',
    username    TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL,
    resource    TEXT NOT NULL DEFAULT '',
    ip_address  TEXT NOT NULL DEFAULT '',
    user_agent  TEXT NOT NULL DEFAULT '',
    success     INTEGER NOT NULL DEFAULT 1,
    fail_reason TEXT NOT NULL DEFAULT '',
    at          DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS backup_codes (
    id       TEXT PRIMARY KEY,
    user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_user_id    ON auth_audit(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_at         ON auth_audit(at);
CREATE INDEX IF NOT EXISTS idx_backup_codes_uid ON backup_codes(user_id);
`
	_, err := s.db.Exec(schema)
	return err
}

// ─── User Operations ──────────────────────────────────────────────────────────

func (s *Store) CreateUser(u *User) error {
	s.usersMu.Lock()
	defer s.usersMu.Unlock()

	if _, exists := s.byName[u.Username]; exists {
		return ErrUserExists
	}
	if _, exists := s.byEmail[u.Email]; exists {
		return ErrUserExists
	}

	u.ID        = newID()
	u.CreatedAt = time.Now().UTC()
	u.UpdatedAt = u.CreatedAt

	_, err := s.db.Exec(`
		INSERT INTO users
		(id, username, email, password_hash, role, active, locked,
		 failed_attempts, display_name, totp_secret, totp_enabled,
		 created_at, updated_at, created_by)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		u.ID, u.Username, u.Email, u.PasswordHash,
		string(u.Role), boolToInt(u.Active), boolToInt(u.Locked),
		u.FailedAttempts, u.DisplayName, u.TOTPSecret,
		boolToInt(u.TOTPEnabled), u.CreatedAt, u.UpdatedAt, u.CreatedBy,
	)
	if err != nil {
		return fmt.Errorf("DB insert user: %w", err)
	}

	// Update memory cache
	s.users[u.ID]         = u
	s.byName[u.Username]  = u.ID
	s.byEmail[u.Email]    = u.ID
	return nil
}

func (s *Store) GetUserByID(id string) (*User, error) {
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil, ErrUserNotFound
	}
	copy := *u
	return &copy, nil
}

func (s *Store) GetUserByUsername(username string) (*User, error) {
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()
	id, ok := s.byName[username]
	if !ok {
		return nil, ErrUserNotFound
	}
	copy := *s.users[id]
	return &copy, nil
}

func (s *Store) ListUsers() []*User {
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()
	list := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		c := *u
		list = append(list, &c)
	}
	return list
}

func (s *Store) UpdateUser(u *User) error {
	s.usersMu.Lock()
	defer s.usersMu.Unlock()
	u.UpdatedAt = time.Now().UTC()
	_, err := s.db.Exec(`
		UPDATE users SET role=?, active=?, locked=?, failed_attempts=?,
		display_name=?, totp_enabled=?, last_login=?, updated_at=?
		WHERE id=?`,
		string(u.Role), boolToInt(u.Active), boolToInt(u.Locked),
		u.FailedAttempts, u.DisplayName, boolToInt(u.TOTPEnabled),
		u.LastLogin, u.UpdatedAt, u.ID,
	)
	if err != nil {
		return err
	}
	s.users[u.ID] = u
	return nil
}

// UpdateTOTPSecret atomically sets the user's TOTP secret and enabled flag.
// Called once the operator confirms the first valid code during enrollment.
func (s *Store) UpdateTOTPSecret(userID, secret string, enabled bool) error {
	s.usersMu.Lock()
	defer s.usersMu.Unlock()
	now := time.Now().UTC()
	_, err := s.db.Exec(
		`UPDATE users SET totp_secret=?, totp_enabled=?, updated_at=? WHERE id=?`,
		secret, boolToInt(enabled), now, userID,
	)
	if err != nil {
		return err
	}
	if u, ok := s.users[userID]; ok {
		u.TOTPSecret  = secret
		u.TOTPEnabled = enabled
		u.UpdatedAt   = now
	}
	return nil
}

// UpdateBackupCodes replaces all backup codes for a user with new hashed codes.
// Called once during TOTP enrollment confirmation.
func (s *Store) UpdateBackupCodes(userID string, hashedCodes []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`DELETE FROM backup_codes WHERE user_id=?`, userID); err != nil {
		return err
	}
	for _, h := range hashedCodes {
		id := newID()
		if _, err := tx.Exec(
			`INSERT INTO backup_codes (id, user_id, code_hash) VALUES (?,?,?)`,
			id, userID, h,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// EnableTOTPWithBackupCodes atomically: sets totp_secret, enables TOTP, and
// replaces all backup codes — all in a single SQLite transaction. Guarantees
// no window where the secret is updated but backup codes are stale/absent.
// Use this at ConfirmTOTPSetup instead of two separate UpdateTOTPSecret +
// UpdateBackupCodes calls.
func (s *Store) EnableTOTPWithBackupCodes(userID, secret string, hashedCodes []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	now := time.Now().UTC()
	if _, err := tx.Exec(
		`UPDATE users SET totp_secret=?, totp_enabled=1, updated_at=? WHERE id=?`,
		secret, now, userID,
	); err != nil {
		return fmt.Errorf("enable TOTP: %w", err)
	}

	if _, err := tx.Exec(`DELETE FROM backup_codes WHERE user_id=?`, userID); err != nil {
		return fmt.Errorf("clear backup codes: %w", err)
	}
	for _, h := range hashedCodes {
		if _, err := tx.Exec(
			`INSERT INTO backup_codes (id, user_id, code_hash) VALUES (?,?,?)`,
			newID(), userID, h,
		); err != nil {
			return fmt.Errorf("insert backup code: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit EnableTOTP: %w", err)
	}

	// Update memory cache atomically after the DB transaction succeeds.
	s.usersMu.Lock()
	if u, ok := s.users[userID]; ok {
		u.TOTPSecret  = secret
		u.TOTPEnabled = true
		u.UpdatedAt   = now
	}
	s.usersMu.Unlock()
	return nil
}

// DisableTOTP atomically clears the TOTP secret, disables the flag, and
// removes all backup codes for userID. Used by super_admin for account recovery.
func (s *Store) DisableTOTP(userID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	now := time.Now().UTC()
	if _, err := tx.Exec(
		`UPDATE users SET totp_secret='', totp_enabled=0, updated_at=? WHERE id=?`,
		now, userID,
	); err != nil {
		return fmt.Errorf("clear TOTP secret: %w", err)
	}
	if _, err := tx.Exec(
		`DELETE FROM backup_codes WHERE user_id=?`, userID,
	); err != nil {
		return fmt.Errorf("clear backup codes: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit DisableTOTP: %w", err)
	}

	s.usersMu.Lock()
	if u, ok := s.users[userID]; ok {
		u.TOTPSecret  = ""
		u.TOTPEnabled = false
		u.UpdatedAt   = now
	}
	s.usersMu.Unlock()
	return nil
}

func (s *Store) UpdatePasswordHash(userID, hash string) error {
	s.usersMu.Lock()
	defer s.usersMu.Unlock()
	_, err := s.db.Exec(
		`UPDATE users SET password_hash=?, updated_at=? WHERE id=?`,
		hash, time.Now().UTC(), userID,
	)
	if err != nil {
		return err
	}
	if u, ok := s.users[userID]; ok {
		u.PasswordHash = hash
	}
	return nil
}

// ─── Session Operations ───────────────────────────────────────────────────────

func (s *Store) CreateSession(sess *Session) error {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	sess.ID        = newID()
	sess.CreatedAt = time.Now().UTC()
	sess.LastActivityAt = sess.CreatedAt

	_, err := s.db.Exec(`
		INSERT INTO sessions
		(id, user_id, refresh_token_hash, user_agent, ip_address,
		 created_at, last_activity_at, expires_at, revoked)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		sess.ID, sess.UserID, sess.RefreshToken,
		sess.UserAgent, sess.IPAddress,
		sess.CreatedAt, sess.LastActivityAt,
		sess.ExpiresAt, boolToInt(sess.Revoked),
	)
	if err != nil {
		return fmt.Errorf("DB insert session: %w", err)
	}

	s.sessions[sess.ID] = sess
	return nil
}

func (s *Store) GetSession(sessionID string) (*Session, error) {
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}
	if sess.Revoked {
		return nil, ErrSessionRevoked
	}
	if sess.IsExpired() {
		return nil, ErrSessionExpired
	}
	if sess.IsInactive(s.inactivityTimeout) {
		return nil, ErrInactivityTimeout
	}
	c := *sess
	return &c, nil
}

func (s *Store) TouchSession(sessionID string) error {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}
	sess.LastActivityAt = time.Now().UTC()
	_, err := s.db.Exec(
		`UPDATE sessions SET last_activity_at=? WHERE id=?`,
		sess.LastActivityAt, sessionID,
	)
	return err
}

func (s *Store) RevokeSession(sessionID string) error {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	if sess, ok := s.sessions[sessionID]; ok {
		sess.Revoked = true
	}
	_, err := s.db.Exec(
		`UPDATE sessions SET revoked=1 WHERE id=?`, sessionID)
	return err
}

func (s *Store) RevokeAllUserSessions(userID string) error {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	for _, sess := range s.sessions {
		if sess.UserID == userID {
			sess.Revoked = true
		}
	}
	_, err := s.db.Exec(
		`UPDATE sessions SET revoked=1 WHERE user_id=?`, userID)
	return err
}

// ─── Audit Log ────────────────────────────────────────────────────────────────
func (s *Store) WriteAuditEvent(ev AuthAuditEvent) {
	ev.ID = newID()
	ev.At = time.Now().UTC()
	_, err := s.db.Exec(`
		INSERT INTO auth_audit
		(id, user_id, username, action, resource, ip_address, user_agent, success, fail_reason, at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		ev.ID, ev.UserID, ev.Username, ev.Action, ev.Resource,
		ev.IPAddress, ev.UserAgent, boolToInt(ev.Success), ev.FailReason, ev.At,
	)
	if err != nil {
		s.log.Error("Audit write failed", zap.Error(err))
	}
}

func (s *Store) GetAuditEvents(limit int) ([]AuthAuditEvent, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, username, action, resource, ip_address,
		        user_agent, success, fail_reason, at
		 FROM auth_audit ORDER BY at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []AuthAuditEvent
	for rows.Next() {
		var ev AuthAuditEvent
		var success int
		if err := rows.Scan(
			&ev.ID, &ev.UserID, &ev.Username, &ev.Action,
			&ev.Resource, &ev.IPAddress, &ev.UserAgent,
			&success, &ev.FailReason, &ev.At,
		); err != nil {
			return nil, fmt.Errorf("scan audit row: %w", err)
		}
		ev.Success = success == 1
		events = append(events, ev)
	}
	return events, rows.Err()
}

// ─── Login Attempt Tracking ───────────────────────────────────────────────────
const maxFailedAttempts = 5

func (s *Store) RecordFailedLogin(userID string) error {
	// Capture snapshot values under the lock; do DB I/O outside to avoid
	// holding the lock during blocking writes.
	var (
		attempts  int
		locked    bool
		updatedAt time.Time
	)

	s.usersMu.Lock()
	u, ok := s.users[userID]
	if ok {
		u.FailedAttempts++
		if u.FailedAttempts >= maxFailedAttempts {
			u.Locked = true
			s.log.Warn("Account locked after failed attempts",
				zap.String("user_id", userID),
				zap.Int("attempts", u.FailedAttempts),
			)
		}
		u.UpdatedAt = time.Now().UTC()
		attempts  = u.FailedAttempts
		locked    = u.Locked
		updatedAt = u.UpdatedAt
	}
	s.usersMu.Unlock()

	if !ok {
		return ErrUserNotFound
	}
	_, err := s.db.Exec(
		`UPDATE users SET failed_attempts=?, locked=?, updated_at=? WHERE id=?`,
		attempts, boolToInt(locked), updatedAt, userID,
	)
	return err
}

func (s *Store) ResetFailedLogin(userID string) error {
	var (
		updatedAt time.Time
		found     bool
	)

	s.usersMu.Lock()
	if u, ok := s.users[userID]; ok {
		u.FailedAttempts = 0
		u.UpdatedAt     = time.Now().UTC()
		updatedAt       = u.UpdatedAt
		found           = true
	}
	s.usersMu.Unlock()

	if !found {
		return ErrUserNotFound
	}
	_, err := s.db.Exec(
		`UPDATE users SET failed_attempts=0, updated_at=? WHERE id=?`,
		updatedAt, userID,
	)
	return err
}

// ─── Dev Mode ─────────────────────────────────────────────────────────────────

// DevTOTPSecret is the fixed TOTP secret injected on the admin account when the
// daemon starts in dev mode (FALX_DEV=1 / --dev). Never changes between restarts,
// so any TOTP app seeded with this key stays in sync indefinitely.
// PRODUCTION: this constant must never appear in a prod config or log.
const DevTOTPSecret = "KVKVEU2HKVKTEMKS"

// DevModeBootstrap is called on startup when FALX_DEV=1.
// It performs three operations atomically in the DB, then syncs the in-memory cache:
//  1. Clears locked=1 and failed_attempts on every user account.
//  2. Forces the "admin" account to use DevTOTPSecret with totp_enabled=1.
// This lets developers restart the daemon and immediately log in using the
// printed 6-digit code without touching the database manually.
func (s *Store) DevModeBootstrap() error {
	now := time.Now().UTC()

	// 1. Unlock all accounts and reset failed-attempt counters.
	if _, err := s.db.Exec(
		`UPDATE users SET locked=0, failed_attempts=0, updated_at=?`, now,
	); err != nil {
		return fmt.Errorf("dev bootstrap: clear locks: %w", err)
	}

	// 2. Pin admin TOTP to the well-known dev secret.
	if _, err := s.db.Exec(
		`UPDATE users SET totp_secret=?, totp_enabled=1, updated_at=? WHERE username='admin'`,
		DevTOTPSecret, now,
	); err != nil {
		return fmt.Errorf("dev bootstrap: set admin TOTP: %w", err)
	}

	// 3. Sync in-memory cache.
	s.usersMu.Lock()
	for _, u := range s.users {
		u.Locked         = false
		u.FailedAttempts = 0
		u.UpdatedAt      = now
	}
	if id, ok := s.byName["admin"]; ok {
		if u, ok := s.users[id]; ok {
			u.TOTPSecret  = DevTOTPSecret
			u.TOTPEnabled = true
		}
	}
	s.usersMu.Unlock()

	return nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
func (s *Store) loadCache() error {
	rows, err := s.db.Query(`
		SELECT id, username, email, password_hash, role, active, locked,
		       failed_attempts, display_name, totp_secret, totp_enabled,
		       COALESCE(last_login, ''), created_at, updated_at, created_by
		FROM users`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		u := &User{}
		var active, locked, totpEnabled int
		var lastLogin string
		if err := rows.Scan(
			&u.ID, &u.Username, &u.Email, &u.PasswordHash,
			&u.Role, &active, &locked, &u.FailedAttempts,
			&u.DisplayName, &u.TOTPSecret, &totpEnabled,
			&lastLogin, &u.CreatedAt, &u.UpdatedAt, &u.CreatedBy,
		); err != nil {
			return fmt.Errorf("scan user row: %w", err)
		}
		u.Active      = active == 1
		u.Locked      = locked == 1
		u.TOTPEnabled = totpEnabled == 1
		s.users[u.ID]        = u
		s.byName[u.Username] = u.ID
		s.byEmail[u.Email]   = u.ID
	}
	return rows.Err()
}

func (s *Store) ensureDefaultAdmin() {
	s.usersMu.RLock()
	_, exists := s.byName["admin"]
	s.usersMu.RUnlock()
	if exists {
		return
	}

	// Create default super_admin with a random password
	password := generateTempPassword()
	hash, err := HashPassword(password)
	if err != nil {
		s.log.Error("Default admin password hash failed", zap.Error(err))
		return
	}

	admin := &User{
		Username:    "admin",
		Email:       "admin@falx.local",
		PasswordHash: hash,
		Role:        RoleSuperAdmin,
		Active:      true,
		DisplayName: "System Administrator",
		CreatedBy:   "system",
	}

	if err := s.CreateUser(admin); err != nil {
		s.log.Error("Default admin creation failed", zap.Error(err))
		return
	}

	s.log.Warn("═══════════════════════════════════════════════════════",
	)
	s.log.Warn("DEFAULT ADMIN CREATED — CHANGE PASSWORD IMMEDIATELY",
		zap.String("username", "admin"),
		zap.String("temp_password", password),
	)
	s.log.Warn("═══════════════════════════════════════════════════════")
}

func generateTempPassword() string {
	b := make([]byte, 12)
	rand.Read(b)
	return "FLX-" + hex.EncodeToString(b[:6]) + "!"
}

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
