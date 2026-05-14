// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Security API handler (soc-backend/internal/api/security_handler.go).
// =============================================================================

package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"

	authpkg "github.com/ft-1/falx-v2/control-plane/pkg/auth"
	"github.com/ft-1/falx-v2/control-plane/pkg/bpfmaps"
	"github.com/ft-1/falx-v2/control-plane/pkg/events"
)

type SecurityHandler struct {
	bpfMgr *bpfmaps.Manager
	bus    *events.Bus
	log    *zap.Logger
}

func NewSecurityHandler(mgr *bpfmaps.Manager, bus *events.Bus, log *zap.Logger) *SecurityHandler {
	return &SecurityHandler{bpfMgr: mgr, bus: bus, log: log}
}

// GET /api/v1/security/blocklist
func (h *SecurityHandler) ListBlocked(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"entries":   []interface{}{},
		"total":     0,
		"timestamp": time.Now().UTC(),
	})
}

// POST /api/v1/security/block
func (h *SecurityHandler) BlockIP(w http.ResponseWriter, r *http.Request) {
	claims := authpkg.ClaimsFromContext(r.Context())
	var req struct {
		IP          string `json:"ip"`
		TTLSeconds  uint64 `json:"ttl_s"`
		ThreatScore uint8  `json:"threat_score"`
		Reason      string `json:"reason"`
		RuleID      uint8  `json:"rule_id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	ip := net.ParseIP(req.IP)
	if ip == nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_ip", "Invalid IP: "+req.IP)
		return
	}

	// Analysts limited to 24-hour max
	if claims.Role == authpkg.RoleAnalyst {
		if req.TTLSeconds == 0 || req.TTLSeconds > 86400 {
			req.TTLSeconds = 86400
		}
	}

	if h.bpfMgr == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "bpf_unavailable", "BPF maps not accessible")
		return
	}

	entry := bpfmaps.BlockEntry{
		Action:      bpfmaps.ActionDrop,
		RuleID:      req.RuleID,
		ThreatScore: req.ThreatScore,
		ExpireAt:    req.TTLSeconds,
		Reason:      bpfmaps.ReasonAIVerdict,
	}
	actor := fmt.Sprintf("soc:%s", claims.UserID)

	if err := h.bpfMgr.BlockIPv4(ip, entry, actor); err != nil {
		writeAPIError(w, http.StatusTooManyRequests, "block_failed", err.Error())
		return
	}

	h.bus.Publish(events.IPBlockedEvent(ip.String(), actor, req.Reason, req.TTLSeconds))
	h.log.Info("IP blocked via SOC", zap.String("ip", ip.String()),
		zap.String("actor", claims.UserID), zap.Uint64("ttl", req.TTLSeconds))

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":   "IP blocked",
		"ip":        ip.String(),
		"ttl_s":     req.TTLSeconds,
		"permanent": req.TTLSeconds == 0,
	})
}

// DELETE /api/v1/security/block/{ip}
func (h *SecurityHandler) UnblockIP(w http.ResponseWriter, r *http.Request) {
	claims := authpkg.ClaimsFromContext(r.Context())
	ipStr  := mux.Vars(r)["ip"]

	ip := net.ParseIP(ipStr)
	if ip == nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_ip", "Invalid IP: "+ipStr)
		return
	}
	if h.bpfMgr == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "bpf_unavailable", "")
		return
	}

	actor := fmt.Sprintf("soc:%s", claims.UserID)
	if err := h.bpfMgr.UnblockIPv4(ip, actor); err != nil {
		writeAPIError(w, http.StatusNotFound, "unblock_failed", err.Error())
		return
	}

	h.bus.Publish(events.IPUnblockedEvent(ip.String(), actor))
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "IP unblocked", "ip": ip.String(),
	})
}

// POST /api/v1/security/redirect
func (h *SecurityHandler) RedirectIP(w http.ResponseWriter, r *http.Request) {
	claims := authpkg.ClaimsFromContext(r.Context())
	var req struct {
		IP         string `json:"ip"`
		TTLSeconds uint64 `json:"ttl_s"`
		Reason     string `json:"reason"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	ip := net.ParseIP(req.IP)
	if ip == nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_ip", req.IP)
		return
	}
	if h.bpfMgr == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "bpf_unavailable", "")
		return
	}

	entry := bpfmaps.BlockEntry{
		Action:   bpfmaps.ActionRedirect,
		ExpireAt: req.TTLSeconds,
		Reason:   bpfmaps.ReasonAIVerdict,
	}
	actor := fmt.Sprintf("soc:%s", claims.UserID)
	if err := h.bpfMgr.BlockIPv4(ip, entry, actor); err != nil {
		writeAPIError(w, http.StatusTooManyRequests, "redirect_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "IP redirected to honeypot", "ip": ip.String(),
	})
}

// GET /api/v1/security/rate-buckets
func (h *SecurityHandler) RateBuckets(w http.ResponseWriter, r *http.Request) {
	if h.bpfMgr == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"rate_limiter_stats": map[string]interface{}{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"rate_limiter_stats": h.bpfMgr.RateLimiterStats(),
		"timestamp":          time.Now().UTC(),
	})
}

// GET /api/v1/security/honeypot/sessions
func (h *SecurityHandler) HoneypotSessions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"sessions": []interface{}{}, "total": 0, "timestamp": time.Now().UTC(),
	})
}

// GET /api/v1/security/stats
func (h *SecurityHandler) SecurityStats(w http.ResponseWriter, r *http.Request) {
	if h.bpfMgr == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"note": "BPF unavailable"})
		return
	}
	stats, err := h.bpfMgr.ReadStats()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "stats_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"xdp": map[string]uint64{
			"rx_packets":     stats.RxPackets,
			"rx_bytes":       stats.RxBytes,
			"dropped":        stats.Dropped,
			"rate_limited":   stats.RateLimited,
			"passed":         stats.Passed,
			"redirected":     stats.Redirected,
			"failsafe_drops": stats.FailsafeDrops,
			"parse_errors":   stats.ParseErrors,
		},
		"timestamp": time.Now().UTC(),
	})
}

// GET /api/v1/failsafe
func (h *SecurityHandler) FailsafeStatus(w http.ResponseWriter, r *http.Request) {
	if h.bpfMgr == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"circuit_open": false, "note": "BPF unavailable",
		})
		return
	}
	state, err := h.bpfMgr.ReadFailsafeState()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failsafe_read_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"circuit_open":  state.CircuitOpen == 1,
		"current_pps":   state.CurrentPPS,
		"current_bps":   state.CurrentBPS,
		"pps_threshold": state.PPSThreshold,
		"bps_threshold": state.BPSThreshold,
		"open_since_ns": state.OpenSinceNs,
		"timestamp":     time.Now().UTC(),
	})
}

// POST /api/v1/failsafe/open
func (h *SecurityHandler) ForceOpenCircuit(w http.ResponseWriter, r *http.Request) {
	claims := authpkg.ClaimsFromContext(r.Context())
	var req struct{ Reason string `json:"reason"` }
	json.NewDecoder(r.Body).Decode(&req)

	if h.bpfMgr == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "bpf_unavailable", "")
		return
	}
	reason := fmt.Sprintf("soc_manual:%s:%s", claims.UserID, req.Reason)
	if err := h.bpfMgr.SetCircuitOpen(true, reason); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failsafe_failed", err.Error())
		return
	}
	h.bus.Publish(events.CircuitOpenEvent(0, reason))
	h.log.Warn("Circuit breaker FORCE OPENED via SOC",
		zap.String("actor", claims.UserID), zap.String("reason", req.Reason))
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Circuit breaker opened — XDP in pure-drop mode", "reason": reason,
	})
}

// POST /api/v1/failsafe/close
func (h *SecurityHandler) ForceCloseCircuit(w http.ResponseWriter, r *http.Request) {
	claims := authpkg.ClaimsFromContext(r.Context())
	if h.bpfMgr == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "bpf_unavailable", "")
		return
	}
	reason := fmt.Sprintf("soc_manual:%s", claims.UserID)
	if err := h.bpfMgr.SetCircuitOpen(false, reason); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failsafe_failed", err.Error())
		return
	}
	h.bus.Publish(events.CircuitClosedEvent(0))
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Circuit breaker closed — AI inference restored",
	})
}

// PUT /api/v1/failsafe/thresholds
func (h *SecurityHandler) UpdateThresholds(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PPSThreshold uint64 `json:"pps_threshold"`
		BPSThreshold uint64 `json:"bps_threshold"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.PPSThreshold == 0 || req.BPSThreshold == 0 {
		writeAPIError(w, http.StatusBadRequest, "invalid_thresholds",
			"Both pps_threshold and bps_threshold must be > 0")
		return
	}
	if h.bpfMgr == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "bpf_unavailable", "")
		return
	}
	if err := h.bpfMgr.UpdateFailsafeThresholds(req.PPSThreshold, req.BPSThreshold); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "update_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":       "Failsafe thresholds updated",
		"pps_threshold": req.PPSThreshold,
		"bps_threshold": req.BPSThreshold,
	})
}
