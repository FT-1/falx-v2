// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Dashboard handler (soc-backend/internal/api/dashboard_handler.go).
//              Aggregates data from BPF maps, policy engine, and event history
//              into role-aware dashboard views.
// =============================================================================

package api

import (
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/ft-1/falx-v2/control-plane/pkg/bpfmaps"
	"github.com/ft-1/falx-v2/control-plane/pkg/events"
	"github.com/ft-1/falx-v2/control-plane/pkg/policy"
)

type DashboardHandler struct {
	bpfMgr    *bpfmaps.Manager
	policyEng *policy.Engine
	bus       *events.Bus
	log       *zap.Logger
}

func NewDashboardHandler(
	mgr *bpfmaps.Manager,
	eng *policy.Engine,
	bus *events.Bus,
	log *zap.Logger,
) *DashboardHandler {
	return &DashboardHandler{bpfMgr: mgr, policyEng: eng, bus: bus, log: log}
}

// ─── GET /api/v1/dashboard ────────────────────────────────────────────────────
// Overview: aggregated snapshot for the main dashboard panel.
func (h *DashboardHandler) Overview(w http.ResponseWriter, r *http.Request) {
	overview := map[string]interface{}{
		"timestamp": time.Now().UTC(),
		"version":   "0.1.0",
		"architect": "FT-1",
	}

	// XDP stats
	if h.bpfMgr != nil {
		if stats, err := h.bpfMgr.ReadStats(); err == nil {
			overview["xdp"] = map[string]uint64{
				"rx_packets":     stats.RxPackets,
				"rx_bytes":       stats.RxBytes,
				"dropped":        stats.Dropped,
				"rate_limited":   stats.RateLimited,
				"passed":         stats.Passed,
				"redirected":     stats.Redirected,
				"failsafe_drops": stats.FailsafeDrops,
			}
		}
		// Failsafe
		if fs, err := h.bpfMgr.ReadFailsafeState(); err == nil {
			overview["failsafe"] = map[string]interface{}{
				"circuit_open": fs.CircuitOpen == 1,
				"current_pps": fs.CurrentPPS,
				"current_bps": fs.CurrentBPS,
			}
		}
		// Rate limiter
		overview["rate_limiter"] = h.bpfMgr.RateLimiterStats()
	}

	// Policy stats
	if h.policyEng != nil {
		s := h.policyEng.Stats()
		overview["policy"] = map[string]interface{}{
			"total_rules":   s.TotalRules,
			"enabled_rules": s.EnabledRules,
			"total_evals":   s.TotalEvals,
			"total_hits":    s.TotalHits,
			"hit_rate":      s.HitRate,
		}
	}

	// Event bus health
	overview["event_bus"] = map[string]interface{}{
		"drops": h.bus.DropCount(),
	}

	writeJSON(w, http.StatusOK, overview)
}

// ─── GET /api/v1/dashboard/stats ─────────────────────────────────────────────
func (h *DashboardHandler) Stats(w http.ResponseWriter, r *http.Request) {
	if h.bpfMgr == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"note": "BPF unavailable — stub mode", "timestamp": time.Now().UTC(),
		})
		return
	}
	stats, err := h.bpfMgr.ReadStats()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "stats_error", err.Error())
		return
	}

	// Calculate derived metrics
	total    := stats.RxPackets
	dropPct  := 0.0
	if total > 0 {
		drops   := stats.Dropped + stats.RateLimited + stats.FailsafeDrops
		dropPct  = float64(drops) / float64(total) * 100
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"rx_packets":        stats.RxPackets,
		"rx_bytes":          stats.RxBytes,
		"rx_mbps":           float64(stats.RxBytes) * 8 / 1_000_000,
		"dropped":           stats.Dropped,
		"rate_limited":      stats.RateLimited,
		"failsafe_drops":    stats.FailsafeDrops,
		"passed":            stats.Passed,
		"redirected":        stats.Redirected,
		"parse_errors":      stats.ParseErrors,
		"drop_percentage":   dropPct,
		"timestamp":         time.Now().UTC(),
	})
}

// ─── GET /api/v1/dashboard/threats ───────────────────────────────────────────
func (h *DashboardHandler) Threats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"active_threats": []interface{}{},
		"threat_level":   computeThreatLevel(h.bpfMgr),
		"timestamp":      time.Now().UTC(),
	})
}

// ─── GET /api/v1/dashboard/timeline ──────────────────────────────────────────
func (h *DashboardHandler) Timeline(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"events":    []interface{}{},
		"timestamp": time.Now().UTC(),
	})
}

// ─── Threat Level Calculator ──────────────────────────────────────────────────
func computeThreatLevel(mgr *bpfmaps.Manager) string {
	if mgr == nil {
		return "unknown"
	}
	fs, err := mgr.ReadFailsafeState()
	if err != nil {
		return "unknown"
	}
	if fs.CircuitOpen == 1 {
		return "critical"
	}
	stats, err := mgr.ReadStats()
	if err != nil {
		return "unknown"
	}
	if stats.RxPackets == 0 {
		return "low"
	}
	totalDrops := stats.Dropped + stats.RateLimited
	ratio       := float64(totalDrops) / float64(stats.RxPackets)
	switch {
	case ratio > 0.5:  return "high"
	case ratio > 0.2:  return "medium"
	default:           return "low"
	}
}
