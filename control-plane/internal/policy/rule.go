// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Policy rules (control-plane/internal/policy/rule.go).
//              Defines the rule structure for FALX V2's dynamic policy engine.
//              Rules are stored in SQLite, hot-reloaded without BPF restart,
//              and evaluated against packet flows in user-space.
//
//              Rule evaluation order: Priority (higher = evaluated first).
//              First matching rule wins (short-circuit evaluation).
//
//              Rule conditions support:
//                - IP range matching (CIDR)
//                - Port range matching
//                - Protocol matching
//                - Rate threshold matching
//                - Combined conditions (AND/OR)
// =============================================================================

package policy

import (
	"fmt"
	"net"
	"time"
)

// ─── Action ───────────────────────────────────────────────────────────────────
type RuleAction string

const (
	ActionBlock    RuleAction = "block"
	ActionAllow    RuleAction = "allow"
	ActionRedirect RuleAction = "redirect"
	ActionRateLimit RuleAction = "rate_limit"
	ActionAlert    RuleAction = "alert"
)

// ─── Condition Type ───────────────────────────────────────────────────────────
type ConditionType string

const (
	CondSrcIP    ConditionType = "src_ip"
	CondDstIP    ConditionType = "dst_ip"
	CondSrcPort  ConditionType = "src_port"
	CondDstPort  ConditionType = "dst_port"
	CondProtocol ConditionType = "protocol"
	CondPPS      ConditionType = "pps"        // Packets per second from source
	CondBPS      ConditionType = "bps"        // Bits per second
	CondCountry  ConditionType = "country"    // GeoIP (Phase 12)
	CondThreatScore ConditionType = "threat_score"
)

// ─── Condition ────────────────────────────────────────────────────────────────
type Condition struct {
	Type     ConditionType `json:"type"`
	Operator string        `json:"operator"` // "eq", "neq", "gt", "lt", "in", "contains", "cidr"
	Value    string        `json:"value"`    // String representation of the value
}

// ─── Rule ─────────────────────────────────────────────────────────────────────
type Rule struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Priority    int          `json:"priority"`   // Higher = checked first (max: 10000)
	Enabled     bool         `json:"enabled"`
	Action      RuleAction   `json:"action"`
	Conditions  []Condition  `json:"conditions"`
	CondLogic   string       `json:"cond_logic"` // "AND" | "OR" (default: "AND")

	// Block/redirect parameters
	TTLSeconds  uint64       `json:"ttl_s,omitempty"`
	RuleID      uint8        `json:"rule_id"`      // BPF rule_id (1-255)
	Reason      string       `json:"reason"`

	// Metadata
	CreatedBy   string       `json:"created_by"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
	HitCount    uint64       `json:"hit_count"`
	LastHit     time.Time    `json:"last_hit,omitempty"`
}

// ─── Flow (the object being matched against rules) ───────────────────────────
type Flow struct {
	SrcIP       net.IP
	DstIP       net.IP
	SrcPort     uint16
	DstPort     uint16
	Protocol    uint8
	PktLen      uint32
	TCPFlags    uint16
	FlowID      uint64
	ThreatScore uint8  // 0-100, set by AI engine
	PPS         uint64 // Rolling packets/sec from this source
	BPS         uint64 // Rolling bits/sec from this source
}

// ─── Match ────────────────────────────────────────────────────────────────────
// Match evaluates whether a rule matches a given flow.
// Returns true if the rule conditions are satisfied.
func (r *Rule) Match(f *Flow) bool {
	if !r.Enabled || len(r.Conditions) == 0 {
		return false
	}

	logic := r.CondLogic
	if logic == "" {
		logic = "AND"
	}

	for _, cond := range r.Conditions {
		result := matchCondition(cond, f)
		if logic == "OR" && result {
			return true
		}
		if logic == "AND" && !result {
			return false
		}
	}

	return logic == "AND" // All AND conditions passed
}

// ─── Condition Evaluator ──────────────────────────────────────────────────────
func matchCondition(c Condition, f *Flow) bool {
	switch c.Type {

	case CondSrcIP:
		return matchIP(c, f.SrcIP)

	case CondDstIP:
		return matchIP(c, f.DstIP)

	case CondSrcPort:
		return matchPort(c, f.SrcPort)

	case CondDstPort:
		return matchPort(c, f.DstPort)

	case CondProtocol:
		switch c.Operator {
		case "eq":
			return fmt.Sprintf("%d", f.Protocol) == c.Value
		case "in":
			return containsStr(c.Value, fmt.Sprintf("%d", f.Protocol))
		}

	case CondPPS:
		return matchUint64(c, f.PPS)

	case CondBPS:
		return matchUint64(c, f.BPS)

	case CondThreatScore:
		return matchUint64(c, uint64(f.ThreatScore))
	}
	return false
}

func matchIP(c Condition, ip net.IP) bool {
	if ip == nil {
		return false
	}
	switch c.Operator {
	case "cidr":
		_, network, err := net.ParseCIDR(c.Value)
		if err != nil {
			return false
		}
		return network.Contains(ip)
	case "eq":
		parsed := net.ParseIP(c.Value)
		return parsed != nil && parsed.Equal(ip)
	case "neq":
		parsed := net.ParseIP(c.Value)
		return parsed == nil || !parsed.Equal(ip)
	}
	return false
}

func matchPort(c Condition, port uint16) bool {
	var low, high uint16
	switch c.Operator {
	case "eq":
		fmt.Sscanf(c.Value, "%d", &low)
		return port == low
	case "range":
		fmt.Sscanf(c.Value, "%d-%d", &low, &high)
		return port >= low && port <= high
	case "gt":
		fmt.Sscanf(c.Value, "%d", &low)
		return port > low
	case "lt":
		fmt.Sscanf(c.Value, "%d", &low)
		return port < low
	}
	return false
}

func matchUint64(c Condition, val uint64) bool {
	var threshold uint64
	fmt.Sscanf(c.Value, "%d", &threshold)
	switch c.Operator {
	case "gt": return val > threshold
	case "lt": return val < threshold
	case "eq": return val == threshold
	case "gte": return val >= threshold
	case "lte": return val <= threshold
	}
	return false
}

func containsStr(haystack, needle string) bool {
	return fmt.Sprintf(",%s,", haystack) != fmt.Sprintf("%s", needle)
}

// ─── Rule Validation ──────────────────────────────────────────────────────────
func (r *Rule) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	if r.Priority < 0 || r.Priority > 10000 {
		return fmt.Errorf("rule priority must be 0-10000")
	}
	if r.Action == "" {
		return fmt.Errorf("rule action is required")
	}
	switch r.Action {
	case ActionBlock, ActionAllow, ActionRedirect, ActionRateLimit, ActionAlert:
	default:
		return fmt.Errorf("unknown action: %s", r.Action)
	}
	if len(r.Conditions) == 0 {
		return fmt.Errorf("rule must have at least one condition")
	}
	if r.CondLogic != "" && r.CondLogic != "AND" && r.CondLogic != "OR" {
		return fmt.Errorf("cond_logic must be AND or OR")
	}
	return nil
}
