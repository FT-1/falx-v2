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
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/ft-1/falx-v2/control-plane/pkg/bpfmaps"
	"github.com/ft-1/falx-v2/control-plane/pkg/events"
	"github.com/ft-1/falx-v2/control-plane/pkg/policy"
)

// MetricsRates holds per-second traffic rates computed by the metrics streamer.
// Updated every second; read by Stats() to include live rates in the response.
type MetricsRates struct {
	PPS        float64   `json:"pps"`
	DropPPS    float64   `json:"drop_pps"`
	PassPPS    float64   `json:"pass_pps"`
	LimitedPPS float64   `json:"limited_pps"`
	MBps       float64   `json:"mbps"`
	SampledAt  time.Time `json:"sampled_at"`
}

type DashboardHandler struct {
	bpfMgrMu  sync.RWMutex
	bpfMgr    *bpfmaps.Manager
	policyEng *policy.Engine
	bus       *events.Bus
	log       *zap.Logger

	ratesMu sync.RWMutex
	rates   MetricsRates
}

func NewDashboardHandler(
	mgr *bpfmaps.Manager,
	eng *policy.Engine,
	bus *events.Bus,
	log *zap.Logger,
) *DashboardHandler {
	return &DashboardHandler{bpfMgr: mgr, policyEng: eng, bus: bus, log: log}
}

// SetBPFMgr swaps in a live BPF manager after it becomes available (late-attach).
// Called by runMetricsStreamer when falxd pins its maps after falx-soc started.
func (h *DashboardHandler) SetBPFMgr(mgr *bpfmaps.Manager) {
	h.bpfMgrMu.Lock()
	h.bpfMgr = mgr
	h.bpfMgrMu.Unlock()
}

func (h *DashboardHandler) getBPFMgr() *bpfmaps.Manager {
	h.bpfMgrMu.RLock()
	defer h.bpfMgrMu.RUnlock()
	return h.bpfMgr
}

// UpdateRates is called by the metrics streamer goroutine (in server.go) every
// second with freshly computed per-second rates. Thread-safe.
func (h *DashboardHandler) UpdateRates(r MetricsRates) {
	h.ratesMu.Lock()
	h.rates = r
	h.ratesMu.Unlock()
}

func (h *DashboardHandler) currentRates() MetricsRates {
	h.ratesMu.RLock()
	defer h.ratesMu.RUnlock()
	return h.rates
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
	bpfMgr := h.getBPFMgr()
	if bpfMgr != nil {
		if stats, err := bpfMgr.ReadStats(); err == nil {
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
		if fs, err := bpfMgr.ReadFailsafeState(); err == nil {
			overview["failsafe"] = map[string]interface{}{
				"circuit_open": fs.CircuitOpen == 1,
				"current_pps": fs.CurrentPPS,
				"current_bps": fs.CurrentBPS,
			}
		}
		// Rate limiter
		overview["rate_limiter"] = bpfMgr.RateLimiterStats()
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
	bpfMgr := h.getBPFMgr()
	if bpfMgr == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"note": "BPF unavailable — falxd not running yet", "timestamp": time.Now().UTC(),
		})
		return
	}
	stats, err := bpfMgr.ReadStats()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "stats_error", err.Error())
		return
	}

	dropPct := 0.0
	if stats.RxPackets > 0 {
		// Dropped already includes FailsafeDrops (both come from MAPPED_XDP_STATS
		// hot-path). Adding FailsafeDrops again would double-count them.
		drops   := stats.Dropped + stats.RateLimited
		dropPct = float64(drops) / float64(stats.RxPackets) * 100
	}

	// Per-second rates computed by the metrics streamer goroutine (accurate 1 s
	// rolling window). Falls back to zero until the first streamer tick fires.
	rates := h.currentRates()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		// Cumulative totals (since daemon start)
		"rx_packets":      stats.RxPackets,
		"rx_bytes":        stats.RxBytes,
		"dropped":         stats.Dropped,
		"rate_limited":    stats.RateLimited,
		"failsafe_drops":  stats.FailsafeDrops,
		"passed":          stats.Passed,
		"redirected":      stats.Redirected,
		"parse_errors":    stats.ParseErrors,
		"drop_percentage": dropPct,
		// Per-second rates (rolling 1 s window — use these for PPS displays)
		"pps":         rates.PPS,
		"drop_pps":    rates.DropPPS,
		"pass_pps":    rates.PassPPS,
		"limited_pps": rates.LimitedPPS,
		"mbps":        rates.MBps,
		"rates_at":    rates.SampledAt,
		"timestamp":   time.Now().UTC(),
	})
}

// ─── GET /api/v1/dashboard/threats ───────────────────────────────────────────
func (h *DashboardHandler) Threats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"active_threats": []interface{}{},
		"threat_level":   computeThreatLevel(h.getBPFMgr()),
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
