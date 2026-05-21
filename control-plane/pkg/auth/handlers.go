// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Auth HTTP handlers (control-plane/internal/auth/handlers.go).
//              REST API handlers for all authentication and user management
//              endpoints. All handlers are stateless; session state lives in
//              the Service + Store layer.
//
//              Routes (registered in soc-backend):
//                POST   /api/v1/auth/login         → Login
//                POST   /api/v1/auth/logout        → Logout (current session)
//                POST   /api/v1/auth/logout-all    → Logout all sessions
//                POST   /api/v1/auth/refresh       → Refresh tokens
//                GET    /api/v1/auth/me            → Current user profile
//                PUT    /api/v1/auth/me/password   → Change own password
//
//                GET    /api/v1/users              → List users [admin+]
//                POST   /api/v1/users              → Create user [admin+]
//                GET    /api/v1/users/:id          → Get user [admin+]
//                PUT    /api/v1/users/:id          → Update user [admin+]
//                DELETE /api/v1/users/:id          → Delete user [super_admin]
//                PUT    /api/v1/users/:id/lock     → Lock user [admin+]
//                PUT    /api/v1/users/:id/unlock   → Unlock user [admin+]
//
//                GET    /api/v1/audit              → Audit log [senior_analyst+]
// =============================================================================

package auth

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

// ─── Handler ──────────────────────────────────────────────────────────────────
type Handler struct {
	svc *Service
	log *zap.Logger
}

func NewHandler(svc *Service, log *zap.Logger) *Handler {
	return &Handler{svc: svc, log: log}
}

// ─── POST /api/v1/auth/login ─────────────────────────────────────────────────
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	resp, err := h.svc.Login(req, realIP(r), r.UserAgent())
	if err != nil {
		switch err {
		case ErrInvalidCredentials:
			writeAPIError(w, http.StatusUnauthorized, "invalid_credentials",
				"Invalid username or password")
		case ErrAccountLocked:
			writeAPIError(w, http.StatusForbidden, "account_locked",
				"Account is locked — contact your administrator")
		case ErrTOTPRequired:
			writeAPIError(w, http.StatusUnauthorized, "totp_required",
				"2FA code required — enter your authenticator code")
		default:
			writeAPIError(w, http.StatusTooManyRequests, "rate_limited", err.Error())
		}
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// ─── POST /api/v1/auth/logout ────────────────────────────────────────────────
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	if err := h.svc.Logout(claims.SessionID, claims.UserID, realIP(r)); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "logout_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}

// ─── POST /api/v1/auth/logout-all ────────────────────────────────────────────
func (h *Handler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	if err := h.svc.LogoutAll(claims.UserID, realIP(r)); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "logout_all_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "all sessions revoked"})
}

// ─── POST /api/v1/auth/refresh ───────────────────────────────────────────────
func (h *Handler) RefreshTokens(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID    string `json:"session_id"`
		RefreshToken string `json:"refresh_token"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	pair, err := h.svc.RefreshTokens(req.SessionID, req.RefreshToken, realIP(r))
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, "refresh_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pair)
}

// ─── GET /api/v1/auth/me ─────────────────────────────────────────────────────
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	user, err := h.svc.store.GetUserByID(claims.UserID)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "user_not_found", "")
		return
	}
	writeJSON(w, http.StatusOK, UserToView(user))
}

// ─── PUT /api/v1/auth/me/password ────────────────────────────────────────────
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	var req ChangePasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := h.svc.ChangePassword(claims.UserID, req, realIP(r)); err != nil {
		writeAPIError(w, http.StatusBadRequest, "password_change_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "password changed — all sessions revoked, please log in again",
	})
}

// ─── GET /api/v1/users ───────────────────────────────────────────────────────
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users := h.svc.store.ListUsers()
	views := make([]UserView, 0, len(users))
	for _, u := range users {
		views = append(views, UserToView(u))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"users": views,
		"total": len(views),
	})
}

// ─── POST /api/v1/users ──────────────────────────────────────────────────────
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	var req RegisterRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	view, err := h.svc.Register(req, claims.UserID, realIP(r))
	if err != nil {
		switch err {
		case ErrUserExists:
			writeAPIError(w, http.StatusConflict, "user_exists",
				"Username or email already in use")
		default:
			writeAPIError(w, http.StatusBadRequest, "create_failed", err.Error())
		}
		return
	}
	writeJSON(w, http.StatusCreated, view)
}

// ─── GET /api/v1/users/:id ───────────────────────────────────────────────────
func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	user, err := h.svc.store.GetUserByID(id)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "user_not_found", "")
		return
	}
	writeJSON(w, http.StatusOK, UserToView(user))
}

// ─── PUT /api/v1/users/:id/lock ──────────────────────────────────────────────
func (h *Handler) LockUser(w http.ResponseWriter, r *http.Request) {
	actorClaims := ClaimsFromContext(r.Context())
	targetID    := pathParam(r, "id")

	target, err := h.svc.store.GetUserByID(targetID)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "user_not_found", "")
		return
	}

	actor := &User{Role: actorClaims.Role}
	if !actor.CanManageRole(target.Role) {
		writeAPIError(w, http.StatusForbidden, "forbidden",
			"Cannot manage users with equal or higher role")
		return
	}

	target.Locked = true
	h.svc.store.UpdateUser(target)
	h.svc.store.RevokeAllUserSessions(target.ID)

	h.svc.store.WriteAuditEvent(AuthAuditEvent{
		UserID:    actorClaims.UserID,
		Action:    "user_lock",
		Resource:  target.ID,
		IPAddress: realIP(r),
		Success:   true,
	})
	writeJSON(w, http.StatusOK, map[string]string{"message": "user locked"})
}

// ─── PUT /api/v1/users/:id/unlock ────────────────────────────────────────────
func (h *Handler) UnlockUser(w http.ResponseWriter, r *http.Request) {
	actorClaims := ClaimsFromContext(r.Context())
	targetID    := pathParam(r, "id")

	target, err := h.svc.store.GetUserByID(targetID)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "user_not_found", "")
		return
	}

	target.Locked          = false
	target.FailedAttempts  = 0
	h.svc.store.UpdateUser(target)

	h.svc.store.WriteAuditEvent(AuthAuditEvent{
		UserID:    actorClaims.UserID,
		Action:    "user_unlock",
		Resource:  target.ID,
		IPAddress: realIP(r),
		Success:   true,
	})
	writeJSON(w, http.StatusOK, map[string]string{"message": "user unlocked"})
}

// ─── GET /api/v1/audit ───────────────────────────────────────────────────────
func (h *Handler) GetAuditLog(w http.ResponseWriter, r *http.Request) {
	events, err := h.svc.store.GetAuditEvents(500)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "audit_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"events": events,
		"total":  len(events),
	})
}

// ─── GET /api/v1/auth/roles ──────────────────────────────────────────────────
func (h *Handler) ListRoles(w http.ResponseWriter, r *http.Request) {
	type roleInfo struct {
		Role        Role         `json:"role"`
		Level       int          `json:"level"`
		Permissions []Permission `json:"permissions"`
	}
	roles := []roleInfo{
		{RoleSuperAdmin,    5, RolePermissions[RoleSuperAdmin]},
		{RoleAdmin,         4, RolePermissions[RoleAdmin]},
		{RoleSeniorAnalyst, 3, RolePermissions[RoleSeniorAnalyst]},
		{RoleAnalyst,       2, RolePermissions[RoleAnalyst]},
		{RoleViewer,        1, RolePermissions[RoleViewer]},
	}
	writeJSON(w, http.StatusOK, roles)
}

// ─── HTTP Helpers ─────────────────────────────────────────────────────────────
func decodeJSON(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB limit
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}

// ─── POST /api/v1/auth/totp/begin ────────────────────────────────────────────
// Starts TOTP enrollment for the calling user. Returns the provisioning URI,
// raw base32 secret (for manual entry), and one-time plaintext backup codes.
func (h *Handler) TOTPBegin(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	enroll, err := h.svc.BeginTOTPSetup(claims.UserID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "totp_begin_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"secret":           enroll.Secret,
		"provisioning_uri": enroll.ProvisioningURI,
		"backup_codes":     enroll.BackupCodes,
		"qr_data_uri":      enroll.QRDataURI,
		"username":         enroll.Username,
		"role":             enroll.Role,
	})
}

// ─── POST /api/v1/auth/totp/confirm ──────────────────────────────────────────
// Confirms TOTP enrollment by verifying a live code from the authenticator app.
// Activates 2FA and returns an upgraded access token with tfa_ok=true so the
// frontend can replace the pending token without requiring a re-login.
func (h *Handler) TOTPConfirm(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	var req struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.Code) != 6 {
		writeAPIError(w, http.StatusBadRequest, "invalid_code", "Code must be 6 digits")
		return
	}
	backupCodes, err := h.svc.ConfirmTOTPSetup(claims.UserID, req.Code)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "totp_confirm_failed", err.Error())
		return
	}

	// Issue upgraded token with tfa_ok=true so the frontend can persist it
	// and transition directly to the dashboard without a page reload.
	pair, err := h.svc.IssueUpgradedToken(claims.UserID, claims.SessionID)
	if err != nil {
		h.log.Warn("TOTP confirmed but token upgrade failed",
			zap.String("user_id", claims.UserID), zap.Error(err))
	}

	h.log.Info("TOTP 2FA enabled", zap.String("user_id", claims.UserID))
	resp := map[string]interface{}{
		"message":      "2FA enabled successfully",
		"backup_codes": backupCodes,
	}
	if pair != nil {
		resp["tokens"] = pair
	}
	writeJSON(w, http.StatusOK, resp)
}

// ─── DELETE /api/v1/users/:id/totp ───────────────────────────────────────────
// Disables 2FA for a user (super_admin only). Clears the TOTP secret and backup
// codes, then revokes all active sessions so the user must re-login.
func (h *Handler) TOTPDisable(w http.ResponseWriter, r *http.Request) {
	actorClaims := ClaimsFromContext(r.Context())
	targetID    := pathParam(r, "id")

	if err := h.svc.DisableTOTPSetup(targetID, actorClaims.UserID, realIP(r)); err != nil {
		switch err {
		case ErrUserNotFound:
			writeAPIError(w, http.StatusNotFound, "user_not_found", "")
		default:
			writeAPIError(w, http.StatusInternalServerError, "totp_disable_failed", err.Error())
		}
		return
	}
	h.log.Info("TOTP disabled",
		zap.String("target_user", targetID),
		zap.String("by", actorClaims.UserID),
	)
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "2FA disabled — user sessions revoked, re-login required",
	})
}

func pathParam(r *http.Request, name string) string {
	if vars := mux.Vars(r); len(vars) > 0 {
		return vars[name]
	}
	return ""
}
