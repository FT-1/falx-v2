// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Policy HTTP handlers (control-plane/internal/policy/handlers.go).
//              REST API for dynamic rule management.
//
//              Routes (registered in SOC backend router):
//                GET    /api/v1/policy/rules           → List all rules
//                POST   /api/v1/policy/rules           → Create rule [senior_analyst+]
//                GET    /api/v1/policy/rules/:id       → Get rule
//                PUT    /api/v1/policy/rules/:id       → Update rule [senior_analyst+]
//                DELETE /api/v1/policy/rules/:id       → Delete rule [admin+]
//                POST   /api/v1/policy/rules/:id/enable  → Enable rule
//                POST   /api/v1/policy/rules/:id/disable → Disable rule
//                POST   /api/v1/policy/reload           → Hot-reload [admin+]
//                GET    /api/v1/policy/stats            → Engine statistics
// =============================================================================

package policy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// ─── Handler ──────────────────────────────────────────────────────────────────
type Handler struct {
	engine *Engine
	log    *zap.Logger
}

func NewHandler(engine *Engine, log *zap.Logger) *Handler {
	return &Handler{engine: engine, log: log}
}

// ─── GET /api/v1/policy/rules ─────────────────────────────────────────────────
func (h *Handler) ListRules(w http.ResponseWriter, r *http.Request) {
	rules := h.engine.ListRules()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"rules": rules,
		"total": len(rules),
		"stats": h.engine.Stats(),
	})
}

// ─── POST /api/v1/policy/rules ────────────────────────────────────────────────
func (h *Handler) CreateRule(w http.ResponseWriter, r *http.Request) {
	actorID := userIDFromContext(r)

	var req struct {
		Name        string      `json:"name"`
		Description string      `json:"description"`
		Priority    int         `json:"priority"`
		Action      RuleAction  `json:"action"`
		Conditions  []Condition `json:"conditions"`
		CondLogic   string      `json:"cond_logic"`
		TTLSeconds  uint64      `json:"ttl_s"`
		RuleID      uint8       `json:"rule_id"`
		Reason      string      `json:"reason"`
		Enabled     bool        `json:"enabled"`
	}

	if !decodeJSON(w, r, &req) {
		return
	}

	rule := &Rule{
		Name:        req.Name,
		Description: req.Description,
		Priority:    req.Priority,
		Action:      req.Action,
		Conditions:  req.Conditions,
		CondLogic:   req.CondLogic,
		TTLSeconds:  req.TTLSeconds,
		RuleID:      req.RuleID,
		Reason:      req.Reason,
		Enabled:     req.Enabled,
	}
	if rule.Priority == 0 {
		rule.Priority = 100
	}
	if rule.RuleID == 0 {
		rule.RuleID = 1
	}

	if err := h.engine.CreateRule(rule, actorID); err != nil {
		writeAPIError(w, http.StatusBadRequest, "create_rule_failed", err.Error())
		return
	}

	h.log.Info("Policy rule created via API",
		zap.String("rule_id", rule.ID),
		zap.String("name",    rule.Name),
		zap.String("actor",   actorID),
	)
	writeJSON(w, http.StatusCreated, rule)
}

// ─── GET /api/v1/policy/rules/:id ─────────────────────────────────────────────
func (h *Handler) GetRule(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r)
	rule, err := h.engine.GetRule(id)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "rule_not_found", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

// ─── PUT /api/v1/policy/rules/:id ─────────────────────────────────────────────
func (h *Handler) UpdateRule(w http.ResponseWriter, r *http.Request) {
	actorID := userIDFromContext(r)
	id      := pathParam(r)

	existing, err := h.engine.GetRule(id)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "rule_not_found", err.Error())
		return
	}

	var req Rule
	if !decodeJSON(w, r, &req) {
		return
	}
	req.ID         = existing.ID
	req.CreatedBy  = existing.CreatedBy
	req.CreatedAt  = existing.CreatedAt
	req.HitCount   = existing.HitCount

	if err := h.engine.UpdateRule(&req, actorID); err != nil {
		writeAPIError(w, http.StatusBadRequest, "update_rule_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, &req)
}

// ─── DELETE /api/v1/policy/rules/:id ──────────────────────────────────────────
func (h *Handler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	actorID := userIDFromContext(r)
	id      := pathParam(r)

	if err := h.engine.DeleteRule(id, actorID); err != nil {
		writeAPIError(w, http.StatusNotFound, "delete_rule_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "rule deleted"})
}

// ─── POST /api/v1/policy/rules/:id/enable ────────────────────────────────────
func (h *Handler) EnableRule(w http.ResponseWriter, r *http.Request) {
	h.setRuleEnabled(w, r, true)
}

func (h *Handler) DisableRule(w http.ResponseWriter, r *http.Request) {
	h.setRuleEnabled(w, r, false)
}

func (h *Handler) setRuleEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	actorID := userIDFromContext(r)
	id      := pathParam(r)

	rule, err := h.engine.GetRule(id)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "rule_not_found", err.Error())
		return
	}

	rule.Enabled   = enabled
	rule.UpdatedAt = time.Now().UTC()

	if err := h.engine.UpdateRule(rule, actorID); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "update_failed", err.Error())
		return
	}

	status := "disabled"
	if enabled {
		status = "enabled"
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("rule %s", status),
		"rule_id": id,
	})
}

// ─── POST /api/v1/policy/reload ───────────────────────────────────────────────
func (h *Handler) ReloadRules(w http.ResponseWriter, r *http.Request) {
	if err := h.engine.Reload(); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "reload_failed", err.Error())
		return
	}
	stats := h.engine.Stats()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":       "rules hot-reloaded",
		"active_rules":  stats.EnabledRules,
		"total_rules":   stats.TotalRules,
	})
}

// ─── GET /api/v1/policy/stats ─────────────────────────────────────────────────
func (h *Handler) GetStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.engine.Stats())
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"code":    code,
		"message": message,
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return false
	}
	return true
}

func pathParam(r *http.Request) string {
	parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

func userIDFromContext(r *http.Request) string {
	// Reads actor ID injected by auth middleware
	if v := r.Context().Value("falx_user_id"); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return "unknown"
}
