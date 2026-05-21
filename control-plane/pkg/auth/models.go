// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Authentication & RBAC models (control-plane/internal/auth/models.go).
//              Defines the complete data model for the multi-user security
//              platform:
//
//              Role Hierarchy (highest → lowest privilege):
//                SUPER_ADMIN  → Full system access + user/role management
//                ADMIN        → User management + policy management
//                SENIOR_ANALYST → Block IPs + view all + manage rules
//                ANALYST      → View threats + temporary blocks only
//                VIEWER       → Read-only dashboard access
//
//              Permissions are fine-grained and assigned per role.
//              Every sensitive operation checks permission at the middleware
//              layer BEFORE reaching the handler.
// =============================================================================

package auth

import (
	"time"
)

// ─── Roles ────────────────────────────────────────────────────────────────────
type Role string

const (
	RoleSuperAdmin    Role = "super_admin"
	RoleAdmin         Role = "admin"
	RoleSeniorAnalyst Role = "senior_analyst"
	RoleAnalyst       Role = "analyst"
	RoleViewer        Role = "viewer"
)

func (r Role) String() string { return string(r) }

func (r Role) Level() int {
	switch r {
	case RoleSuperAdmin:    return 5
	case RoleAdmin:         return 4
	case RoleSeniorAnalyst: return 3
	case RoleAnalyst:       return 2
	case RoleViewer:        return 1
	default:                return 0
	}
}

// Requires2FA reports whether 2FA is mandatory for this role. Two-factor auth
// is enforced ONLY for the admin tier (admin, super_admin), which holds the
// high-privilege user/policy/system management permissions. Lower-privilege
// roles (senior_analyst, analyst, viewer) authenticate with username+password
// alone — they are read-only / limited-scope accounts where a TOTP enrollment
// step would add friction without protecting privileged operations.
func (r Role) Requires2FA() bool {
	return r == RoleSuperAdmin || r == RoleAdmin
}

// ─── Permissions ──────────────────────────────────────────────────────────────
type Permission string

const (
	// User management
	PermUserCreate   Permission = "user:create"
	PermUserRead     Permission = "user:read"
	PermUserUpdate   Permission = "user:update"
	PermUserDelete   Permission = "user:delete"
	PermUserList     Permission = "user:list"
	PermRoleAssign   Permission = "role:assign"

	// IP / Policy management
	PermIPBlock      Permission = "ip:block"
	PermIPUnblock    Permission = "ip:unblock"
	PermIPBlockTemp  Permission = "ip:block_temp"   // Analyst-level: limited TTL
	PermPolicyCreate Permission = "policy:create"
	PermPolicyUpdate Permission = "policy:update"
	PermPolicyDelete Permission = "policy:delete"
	PermPolicyRead   Permission = "policy:read"

	// Honeypot management
	PermHoneypotManage Permission = "honeypot:manage"
	PermHoneypotView   Permission = "honeypot:view"

	// Failsafe / Circuit Breaker
	PermFailsafeControl Permission = "failsafe:control" // Open/close circuit manually
	PermFailsafeView    Permission = "failsafe:view"

	// Dashboard / Telemetry
	PermDashboardView   Permission = "dashboard:view"
	PermTelemetryRead   Permission = "telemetry:read"
	PermAuditRead       Permission = "audit:read"
	PermAlertRead       Permission = "alert:read"
	PermAlertAcknowledge Permission = "alert:acknowledge"

	// System administration
	PermSystemConfig    Permission = "system:config"
	PermSystemHealth    Permission = "system:health"
	PermSystemRestart   Permission = "system:restart"
	PermMetricsRead     Permission = "metrics:read"
)

// ─── Role → Permissions mapping ───────────────────────────────────────────────
var RolePermissions = map[Role][]Permission{
	RoleSuperAdmin: {
		// All permissions
		PermUserCreate, PermUserRead, PermUserUpdate, PermUserDelete, PermUserList,
		PermRoleAssign,
		PermIPBlock, PermIPUnblock, PermIPBlockTemp,
		PermPolicyCreate, PermPolicyUpdate, PermPolicyDelete, PermPolicyRead,
		PermHoneypotManage, PermHoneypotView,
		PermFailsafeControl, PermFailsafeView,
		PermDashboardView, PermTelemetryRead, PermAuditRead,
		PermAlertRead, PermAlertAcknowledge,
		PermSystemConfig, PermSystemHealth, PermSystemRestart,
		PermMetricsRead,
	},
	RoleAdmin: {
		PermUserCreate, PermUserRead, PermUserUpdate, PermUserList,
		// Admins can assign up to senior_analyst, not super_admin
		PermRoleAssign,
		PermIPBlock, PermIPUnblock, PermIPBlockTemp,
		PermPolicyCreate, PermPolicyUpdate, PermPolicyDelete, PermPolicyRead,
		PermHoneypotManage, PermHoneypotView,
		PermFailsafeControl, PermFailsafeView,
		PermDashboardView, PermTelemetryRead, PermAuditRead,
		PermAlertRead, PermAlertAcknowledge,
		PermSystemConfig, PermSystemHealth,
		PermMetricsRead,
	},
	RoleSeniorAnalyst: {
		PermIPBlock, PermIPUnblock, PermIPBlockTemp,
		PermPolicyCreate, PermPolicyUpdate, PermPolicyRead,
		PermHoneypotView,
		PermFailsafeControl, PermFailsafeView,
		PermDashboardView, PermTelemetryRead,
		PermAlertRead, PermAlertAcknowledge,
		PermSystemHealth,
		PermMetricsRead,
		PermAuditRead,
	},
	RoleAnalyst: {
		PermIPBlockTemp, // Only temporary blocks (max 24h)
		PermPolicyRead,
		PermHoneypotView,
		PermFailsafeView,
		PermDashboardView, PermTelemetryRead,
		PermAlertRead, PermAlertAcknowledge,
		PermSystemHealth,
	},
	RoleViewer: {
		PermDashboardView, PermTelemetryRead,
		PermAlertRead,
		PermSystemHealth,
		PermPolicyRead,
	},
}

// ─── User ─────────────────────────────────────────────────────────────────────
type User struct {
	ID             string    `json:"id"`
	Username       string    `json:"username"`
	Email          string    `json:"email"`
	PasswordHash   string    `json:"-"`         // Never serialised
	Role           Role      `json:"role"`
	Active         bool      `json:"active"`
	Locked         bool      `json:"locked"`    // Locked after failed attempts
	FailedAttempts int       `json:"-"`
	LastLogin      time.Time `json:"last_login,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	CreatedBy      string    `json:"created_by"`

	// 2FA
	TOTPSecret     string    `json:"-"`         // TOTP secret (encrypted at rest)
	TOTPEnabled    bool      `json:"totp_enabled"`

	// Profile
	DisplayName    string    `json:"display_name"`
	AvatarURL      string    `json:"avatar_url,omitempty"`
}

// HasPermission checks if the user's role includes the given permission.
func (u *User) HasPermission(p Permission) bool {
	perms, ok := RolePermissions[u.Role]
	if !ok {
		return false
	}
	for _, perm := range perms {
		if perm == p {
			return true
		}
	}
	return false
}

// CanManageRole returns true if the user's role is strictly higher than target.
func (u *User) CanManageRole(target Role) bool {
	return u.Role.Level() > target.Level()
}

// ─── Session ──────────────────────────────────────────────────────────────────
type Session struct {
	ID             string    `json:"id"`
	UserID         string    `json:"user_id"`
	RefreshToken   string    `json:"-"`         // Hashed in storage
	UserAgent      string    `json:"user_agent"`
	IPAddress      string    `json:"ip_address"`
	CreatedAt      time.Time `json:"created_at"`
	LastActivityAt time.Time `json:"last_activity_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	Revoked        bool      `json:"revoked"`
}

// IsExpired returns true if the session has expired.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsInactive returns true if the session has been idle beyond the timeout.
func (s *Session) IsInactive(timeout time.Duration) bool {
	return time.Since(s.LastActivityAt) > timeout
}

// ─── Token Scopes ─────────────────────────────────────────────────────────────
const (
	// ScopePreAuth is issued on login before TOTP enrollment is complete.
	// Grants access only to /auth/totp/begin and /auth/totp/confirm.
	ScopePreAuth = "pre_auth"

	// ScopeSession is the full-access scope issued after TOTP is verified.
	ScopeSession = "session"
)

// ─── Token Claims (JWT payload) ───────────────────────────────────────────────
type TokenClaims struct {
	UserID      string       `json:"sub"`
	Username    string       `json:"username"`
	Role        Role         `json:"role"`
	SessionID   string       `json:"sid"`
	IssuedAt    int64        `json:"iat"`
	ExpiresAt   int64        `json:"exp"`
	TokenType   string       `json:"type"`    // "access"
	TFAVerified bool         `json:"tfa_ok"`
	Scope       string       `json:"scope"`
	Permissions []Permission `json:"perms"`
}

// ─── Token Pair ───────────────────────────────────────────────────────────────
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`    // Always "Bearer"
	ExpiresIn    int64     `json:"expires_in"`    // Access token TTL in seconds
	ExpiresAt    time.Time `json:"expires_at"`
}

// ─── Audit Event ──────────────────────────────────────────────────────────────
type AuthAuditEvent struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	Username   string    `json:"username"`
	Action     string    `json:"action"`     // "login", "logout", "block_ip", etc.
	Resource   string    `json:"resource"`   // What was acted upon
	IPAddress  string    `json:"ip_address"`
	UserAgent  string    `json:"user_agent"`
	Success    bool      `json:"success"`
	FailReason string    `json:"fail_reason,omitempty"`
	At         time.Time `json:"at"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// ─── Requests / Responses ─────────────────────────────────────────────────────
type LoginRequest struct {
	Username string `json:"username" validate:"required,min=3,max=64"`
	Password string `json:"password" validate:"required,min=8,max=128"`
	TOTPCode string `json:"totp_code,omitempty"` // Required if 2FA enabled
}

type RegisterRequest struct {
	Username    string `json:"username"     validate:"required,min=3,max=64,alphanum"`
	Email       string `json:"email"        validate:"required,email"`
	Password    string `json:"password"     validate:"required,min=12,max=128"`
	DisplayName string `json:"display_name" validate:"required,min=2,max=100"`
	Role        Role   `json:"role"         validate:"required"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=12,max=128"`
}

type LoginResponse struct {
	Tokens      TokenPair `json:"tokens"`
	User        UserView  `json:"user"`
}

// UserView is the safe public representation of a user (no password/secrets).
type UserView struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	Role        Role      `json:"role"`
	TOTPEnabled bool      `json:"totp_enabled"`
	LastLogin   time.Time `json:"last_login,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

func UserToView(u *User) UserView {
	return UserView{
		ID:          u.ID,
		Username:    u.Username,
		Email:       u.Email,
		DisplayName: u.DisplayName,
		Role:        u.Role,
		TOTPEnabled: u.TOTPEnabled,
		LastLogin:   u.LastLogin,
		CreatedAt:   u.CreatedAt,
	}
}
