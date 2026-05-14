// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Map mutation audit logger (control-plane/internal/bpfmaps/audit.go).
//              Every write to a BPF map produces a structured audit event.
//              Events are written to a rotating audit log file AND emitted
//              to the SOC backend via the telemetry channel (Phase 11).
//
//              Security requirement: audit log must be append-only.
//              Operator accountability: every block/unblock records who/why.
// =============================================================================

package bpfmaps

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ─── Audit Event ──────────────────────────────────────────────────────────────
type AuditEvent struct {
	Timestamp   time.Time `json:"ts"`
	Operation   string    `json:"op"`
	SrcIP       string    `json:"src_ip,omitempty"`
	Action      string    `json:"action,omitempty"`
	RuleID      uint8     `json:"rule_id,omitempty"`
	ThreatScore uint8     `json:"threat_score,omitempty"`
	TTLSeconds  uint64    `json:"ttl_s,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	Actor       string    `json:"actor"` // "ai-engine", "soc-operator", "failsafe"
	Success     bool      `json:"success"`
	Error       string    `json:"error,omitempty"`
	// Circuit breaker events
	CircuitState string `json:"circuit_state,omitempty"`
	CurrentPPS   uint64 `json:"current_pps,omitempty"`
}

// ─── Audit Logger ─────────────────────────────────────────────────────────────
type AuditLogger struct {
	mu       sync.Mutex
	file     *os.File
	log      *zap.Logger
	filePath string
	// Channel for SOC telemetry (Phase 11 will consume this)
	EventCh chan AuditEvent
}

func NewAuditLogger(filePath string, log *zap.Logger) (*AuditLogger, error) {
	f, err := os.OpenFile(filePath,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cannot open audit log %s: %w", filePath, err)
	}
	return &AuditLogger{
		file:     f,
		log:      log,
		filePath: filePath,
		EventCh:  make(chan AuditEvent, 4096),
	}, nil
}

// Log writes an audit event to the log file and the SOC channel.
func (a *AuditLogger) Log(ev AuditEvent) {
	ev.Timestamp = time.Now().UTC()

	data, err := json.Marshal(ev)
	if err != nil {
		a.log.Error("Audit marshal failed", zap.Error(err))
		return
	}

	a.mu.Lock()
	_, werr := fmt.Fprintf(a.file, "%s\n", data)
	a.mu.Unlock()

	if werr != nil {
		a.log.Error("Audit write failed", zap.Error(werr))
	}

	// Non-blocking send to SOC telemetry channel
	select {
	case a.EventCh <- ev:
	default:
		a.log.Warn("Audit SOC channel full — event dropped",
			zap.String("op", ev.Operation))
	}

	a.log.Info("MAP AUDIT",
		zap.String("op", ev.Operation),
		zap.String("src_ip", ev.SrcIP),
		zap.String("actor", ev.Actor),
		zap.Bool("success", ev.Success),
	)
}

// LogBlockIP records a blocklist insertion event.
func (a *AuditLogger) LogBlockIP(ip net.IP, entry BlockEntry, actor string, err error) {
	ev := AuditEvent{
		Operation:   "block_ip",
		SrcIP:       ip.String(),
		Action:      actionName(entry.Action),
		RuleID:      entry.RuleID,
		ThreatScore: entry.ThreatScore,
		TTLSeconds:  entry.ExpireAt,
		Actor:       actor,
		Success:     err == nil,
	}
	if err != nil {
		ev.Error = err.Error()
	}
	a.Log(ev)
}

// LogUnblockIP records a blocklist removal event.
func (a *AuditLogger) LogUnblockIP(ip net.IP, actor string, err error) {
	ev := AuditEvent{
		Operation: "unblock_ip",
		SrcIP:     ip.String(),
		Actor:     actor,
		Success:   err == nil,
	}
	if err != nil {
		ev.Error = err.Error()
	}
	a.Log(ev)
}

// LogCircuitChange records a failsafe state transition.
func (a *AuditLogger) LogCircuitChange(open bool, pps uint64, reason string) {
	state := "closed"
	if open {
		state = "opened"
	}
	a.Log(AuditEvent{
		Operation:    "circuit_breaker",
		CircuitState: state,
		CurrentPPS:   pps,
		Reason:       reason,
		Actor:        "failsafe-engine",
		Success:      true,
	})
}

// LogConfigUpdate records a CONFIG map update.
func (a *AuditLogger) LogConfigUpdate(actor string, err error) {
	ev := AuditEvent{
		Operation: "config_update",
		Actor:     actor,
		Success:   err == nil,
	}
	if err != nil {
		ev.Error = err.Error()
	}
	a.Log(ev)
}

func (a *AuditLogger) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	close(a.EventCh)
	return a.file.Close()
}

func actionName(a uint8) string {
	switch a {
	case ActionPass:
		return "pass"
	case ActionDrop:
		return "drop"
	case ActionRedirect:
		return "redirect"
	case ActionRateLimit:
		return "rate_limit"
	default:
		return "unknown"
	}
}
