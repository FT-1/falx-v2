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
	json.NewEncoder(w).Encode(v)
}

func pathParam(r *http.Request, name string) string {
	if vars := mux.Vars(r); len(vars) > 0 {
		return vars[name]
	}
	return ""
}
