// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: API handlers (soc-backend/internal/api/handlers.go).
//              Notifications, Admin, and System HTTP handlers.
// =============================================================================

package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"

	authpkg       "github.com/ft-1/falx-v2/control-plane/internal/auth"
	"github.com/ft-1/falx-v2/control-plane/internal/bpfmaps"
	"github.com/ft-1/falx-v2/control-plane/internal/notifications"
)

// ─── Shared JSON helpers ──────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"code": code, "message": message})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return false
	}
	return true
}

// ─── Notifications Handler ────────────────────────────────────────────────────

type NotificationsHandler struct {
	mgr *notifications.Manager
	log *zap.Logger
}

func NewNotificationsHandler(mgr *notifications.Manager, log *zap.Logger) *NotificationsHandler {
	return &NotificationsHandler{mgr: mgr, log: log}
}

// GET /api/v1/notifications
func (h *NotificationsHandler) List(w http.ResponseWriter, r *http.Request) {
	limit := 50
	unreadOnly := r.URL.Query().Get("unread") == "true"
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	items := h.mgr.GetNotifications(limit, unreadOnly)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"notifications": items,
		"total":         len(items),
	})
}

// PUT /api/v1/notifications/{id}/read
func (h *NotificationsHandler) MarkRead(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	h.mgr.MarkRead(id)
	writeJSON(w, http.StatusOK, map[string]string{"message": "marked as read"})
}

// GET /api/v1/notifications/unread-count
func (h *NotificationsHandler) UnreadCount(w http.ResponseWriter, r *http.Request) {
	items := h.mgr.GetNotifications(1000, true)
	writeJSON(w, http.StatusOK, map[string]int{"unread_count": len(items)})
}

// ─── Admin Handler ────────────────────────────────────────────────────────────

type AdminHandler struct {
	svc   *authpkg.Service
	store *authpkg.Store
	log   *zap.Logger
}

func NewAdminHandler(svc *authpkg.Service, store *authpkg.Store, log *zap.Logger) *AdminHandler {
	return &AdminHandler{svc: svc, store: store, log: log}
}

// GET /api/v1/users (alias used by server.go router)
func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users := h.store.ListUsers()
	views := make([]authpkg.UserView, 0, len(users))
	for _, u := range users {
		views = append(views, authpkg.UserToView(u))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"users": views,
		"total": len(views),
	})
}

// ─── System Handler ───────────────────────────────────────────────────────────

type SystemHandler struct {
	bpfMgr    *bpfmaps.Manager
	log       *zap.Logger
	startTime time.Time
}

func NewSystemHandler(mgr *bpfmaps.Manager, log *zap.Logger) *SystemHandler {
	return &SystemHandler{bpfMgr: mgr, log: log, startTime: time.Now()}
}

// GET /healthz — liveness probe (no auth required)
func (h *SystemHandler) Liveness(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "ok",
		"uptime":    time.Since(h.startTime).Round(time.Second).String(),
		"timestamp": time.Now().UTC(),
		"architect": "FT-1",
	})
}

// GET /readyz — readiness probe (no auth required)
func (h *SystemHandler) Readiness(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{"server": "ok"}
	allOK  := true

	if h.bpfMgr != nil {
		if _, err := h.bpfMgr.ReadStats(); err != nil {
			checks["bpf_maps"] = "degraded: " + err.Error()
			allOK = false
		} else {
			checks["bpf_maps"] = "ok"
		}
	} else {
		checks["bpf_maps"] = "stub"
	}

	status := http.StatusOK
	if !allOK {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]interface{}{
		"ready":  allOK,
		"checks": checks,
	})
}

// GET /api/v1/system/health
func (h *SystemHandler) Health(w http.ResponseWriter, r *http.Request) {
	subsystems := map[string]string{
		"http_server":   "ok",
		"event_bus":     "ok",
		"notifications": "ok",
	}
	overallStatus := "operational"

	if h.bpfMgr != nil {
		if _, err := h.bpfMgr.ReadStats(); err != nil {
			subsystems["bpf_maps"] = "degraded"
			overallStatus = "degraded"
		} else {
			subsystems["bpf_maps"] = "ok"
		}
	} else {
		subsystems["bpf_maps"] = "stub_mode"
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     overallStatus,
		"uptime":     time.Since(h.startTime).Round(time.Second).String(),
		"version":    "0.1.0",
		"architect":  "FT-1",
		"timestamp":  time.Now().UTC(),
		"subsystems": subsystems,
	})
}

// GET /api/v1/system/config
func (h *SystemHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"note":            "Managed via /etc/falx/falx.toml",
		"reload_endpoint": "POST /api/v1/policy/reload",
		"config_files": []string{
			"/etc/falx/falx.toml",
			"/etc/falx/honeypot.toml",
			"/etc/falx/notifications.toml",
		},
	})
}

// PUT /api/v1/system/config
func (h *SystemHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Edit /etc/falx/falx.toml then send SIGHUP to falxd for live reload",
	})
}

// GET /api/v1/system/metrics-summary
func (h *SystemHandler) MetricsSummary(w http.ResponseWriter, r *http.Request) {
	if h.bpfMgr == nil {
		writeJSON(w, http.StatusOK, map[string]string{"note": "BPF unavailable — stub mode"})
		return
	}
	stats, _ := h.bpfMgr.ReadStats()
	fs,    _ := h.bpfMgr.ReadFailsafeState()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"xdp_stats":      stats,
		"failsafe_state": fs,
		"rl_stats":       h.bpfMgr.RateLimiterStats(),
		"timestamp":      time.Now().UTC(),
	})
}
