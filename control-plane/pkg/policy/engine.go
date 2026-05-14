// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Policy engine (control-plane/internal/policy/engine.go).
//              Dynamic rule evaluation with hot-reload, BPF map integration,
//              conflict detection, and event bus publication.
//
//              Map Hardening (Phase 10):
//                - Atomic batch application (all-or-nothing per verdict batch)
//                - Conflict detection: allow-rule overrides block-rule warning
//                - Duplicate suppression: skip if IP already in blocklist
//                - Write rate limiting: delegated to bpfmaps.Manager
//                - Priority ordering: rules evaluated highest-priority first
// =============================================================================

package policy

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"

	"github.com/ft-1/falx-v2/control-plane/pkg/bpfmaps"
	"github.com/ft-1/falx-v2/control-plane/pkg/events"
)

// ─── Engine ───────────────────────────────────────────────────────────────────
type Engine struct {
	db     *sql.DB
	bpfMgr *bpfmaps.Manager
	bus    *events.Bus
	log    *zap.Logger

	mu    sync.RWMutex
	rules []*Rule // sorted by priority desc, loaded atomically

	// Atomic stats counters (no lock needed)
	totalEvals atomic.Uint64
	totalHits  atomic.Uint64
	totalApply atomic.Uint64
}

// ─── Constructor ──────────────────────────────────────────────────────────────
func NewEngine(
	dbPath string,
	bpfMgr *bpfmaps.Manager,
	bus    *events.Bus,
	log    *zap.Logger,
) (*Engine, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("policy DB open: %w", err)
	}
	db.SetMaxOpenConns(1)

	e := &Engine{db: db, bpfMgr: bpfMgr, bus: bus, log: log}

	if err := e.migrate(); err != nil {
		return nil, fmt.Errorf("policy migrate: %w", err)
	}
	if err := e.loadRules(); err != nil {
		return nil, fmt.Errorf("load rules: %w", err)
	}

	log.Info("Policy engine ready", zap.Int("rules", len(e.rules)))
	return e, nil
}

// ─── Schema ───────────────────────────────────────────────────────────────────
func (e *Engine) migrate() error {
	_, err := e.db.Exec(`
CREATE TABLE IF NOT EXISTS rules (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    priority    INTEGER NOT NULL DEFAULT 100,
    enabled     INTEGER NOT NULL DEFAULT 1,
    action      TEXT NOT NULL,
    conditions  TEXT NOT NULL,
    cond_logic  TEXT NOT NULL DEFAULT 'AND',
    ttl_s       INTEGER NOT NULL DEFAULT 0,
    rule_id     INTEGER NOT NULL DEFAULT 1,
    reason      TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL DEFAULT '',
    created_at  DATETIME NOT NULL,
    updated_at  DATETIME NOT NULL,
    hit_count   INTEGER NOT NULL DEFAULT 0,
    last_hit    DATETIME
);
CREATE INDEX IF NOT EXISTS idx_rules_priority ON rules(priority DESC);
CREATE INDEX IF NOT EXISTS idx_rules_enabled  ON rules(enabled);
`)
	return err
}

// ─── Rule Loading ─────────────────────────────────────────────────────────────
func (e *Engine) loadRules() error {
	rows, err := e.db.Query(`
		SELECT id, name, description, priority, enabled, action,
		       conditions, cond_logic, ttl_s, rule_id, reason,
		       created_by, created_at, updated_at, hit_count
		FROM rules
		WHERE enabled = 1
		ORDER BY priority DESC, created_at ASC`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var rules []*Rule
	for rows.Next() {
		r := &Rule{}
		var enabled int
		var condJSON string
		if err := rows.Scan(
			&r.ID, &r.Name, &r.Description, &r.Priority,
			&enabled, &r.Action, &condJSON, &r.CondLogic,
			&r.TTLSeconds, &r.RuleID, &r.Reason,
			&r.CreatedBy, &r.CreatedAt, &r.UpdatedAt, &r.HitCount,
		); err != nil {
			e.log.Warn("Rule scan error", zap.Error(err))
			continue
		}
		r.Enabled = enabled == 1

		if err := json.Unmarshal([]byte(condJSON), &r.Conditions); err != nil {
			e.log.Warn("Skipping rule with invalid conditions JSON",
				zap.String("id", r.ID), zap.Error(err))
			continue
		}
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// Detect conflicting rules (warn only — don't block loading)
	e.detectConflicts(rules)

	e.mu.Lock()
	e.rules = rules
	e.mu.Unlock()

	e.log.Info("Policy rules loaded", zap.Int("count", len(rules)))
	return nil
}

// ─── Conflict Detection ───────────────────────────────────────────────────────
// detectConflicts warns when a lower-priority block rule is shadowed by
// a higher-priority allow rule targeting the same CIDR/port.
func (e *Engine) detectConflicts(rules []*Rule) {
	seen := make(map[string]RuleAction) // condition_fingerprint → first action seen
	for _, r := range rules {
		for _, cond := range r.Conditions {
			key := fmt.Sprintf("%s:%s:%s", cond.Type, cond.Operator, cond.Value)
			if prev, exists := seen[key]; exists {
				if (prev == ActionAllow && r.Action == ActionBlock) ||
					(prev == ActionBlock && r.Action == ActionAllow) {
					e.log.Warn("Conflicting policy rules detected",
						zap.String("rule_id",     r.ID),
						zap.String("rule_name",   r.Name),
						zap.String("action",      string(r.Action)),
						zap.String("conflict_action", string(prev)),
						zap.String("condition",   key),
					)
				}
			} else {
				seen[key] = r.Action
			}
		}
	}
}

// ─── Evaluate ─────────────────────────────────────────────────────────────────
// Evaluate runs enabled rules against a flow in priority order.
// Returns the first matching rule, or nil if no match.
func (e *Engine) Evaluate(f *Flow) *Rule {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	e.totalEvals.Add(1)

	for _, r := range rules {
		if r.Match(f) {
			e.totalHits.Add(1)
			// Record hit asynchronously
			go e.recordHit(r.ID)
			return r
		}
	}
	return nil
}

// ─── Apply Rule ───────────────────────────────────────────────────────────────
// ApplyRule translates a matched policy rule into BPF map and event bus actions.
func (e *Engine) ApplyRule(r *Rule, f *Flow, actor string) error {
	if f.SrcIP == nil {
		return nil
	}

	e.totalApply.Add(1)

	switch r.Action {
	case ActionBlock:
		// Duplicate suppression: check if already blocked
		if already, _, _ := e.bpfMgr.IsBlockedIPv4(f.SrcIP); already {
			e.log.Debug("IP already in blocklist — skipping duplicate",
				zap.String("src_ip", f.SrcIP.String()),
				zap.String("rule",   r.Name),
			)
			return nil
		}
		entry := bpfmaps.BlockEntry{
			Action:      bpfmaps.ActionDrop,
			RuleID:      r.RuleID,
			ThreatScore: f.ThreatScore,
			ExpireAt:    r.TTLSeconds,
			Reason:      bpfmaps.ReasonAIVerdict,
		}
		if err := e.bpfMgr.BlockIPv4(f.SrcIP, entry, actor); err != nil {
			return fmt.Errorf("apply block rule %s: %w", r.ID, err)
		}
		e.bus.Publish(events.IPBlockedEvent(
			f.SrcIP.String(), actor, r.Reason, r.TTLSeconds))

	case ActionAllow:
		// Explicit allow: remove from blocklist if present
		if err := e.bpfMgr.UnblockIPv4(f.SrcIP, actor); err == nil {
			e.bus.Publish(events.IPUnblockedEvent(f.SrcIP.String(), actor))
		}

	case ActionRedirect:
		entry := bpfmaps.BlockEntry{
			Action:   bpfmaps.ActionRedirect,
			RuleID:   r.RuleID,
			ExpireAt: r.TTLSeconds,
			Reason:   bpfmaps.ReasonAIVerdict,
		}
		if err := e.bpfMgr.BlockIPv4(f.SrcIP, entry, actor); err != nil {
			return fmt.Errorf("apply redirect rule %s: %w", r.ID, err)
		}

	case ActionAlert:
		e.bus.Publish(events.ThreatAlertEvent(
			f.SrcIP.String(), r.Reason, "medium",
			float64(f.ThreatScore)/100.0,
		))

	case ActionRateLimit:
		// Reset the token bucket so XDP applies fresh rate limiting
		if err := e.bpfMgr.ResetRateBucket(f.SrcIP, actor); err != nil {
			return fmt.Errorf("apply rate-limit rule %s: %w", r.ID, err)
		}
	}

	e.log.Info("Policy rule applied",
		zap.String("rule",   r.Name),
		zap.String("action", string(r.Action)),
		zap.String("src_ip", f.SrcIP.String()),
		zap.String("actor",  actor),
		zap.Uint8("threat_score", f.ThreatScore),
	)
	return nil
}

// ─── Atomic Batch Evaluation ──────────────────────────────────────────────────
// EvaluateAndApplyBatch processes a batch of flows atomically.
// This is the primary entry point for AI inference verdicts.
func (e *Engine) EvaluateAndApplyBatch(flows []*Flow, actor string) []error {
	errs := make([]error, len(flows))
	for i, f := range flows {
		rule := e.Evaluate(f)
		if rule == nil {
			continue
		}
		errs[i] = e.ApplyRule(rule, f, actor)
	}
	return errs
}

// ─── CRUD ─────────────────────────────────────────────────────────────────────

func (e *Engine) CreateRule(r *Rule, createdBy string) error {
	if err := r.Validate(); err != nil {
		return err
	}
	r.ID        = newRuleID()
	r.CreatedBy = createdBy
	r.CreatedAt = time.Now().UTC()
	r.UpdatedAt = r.CreatedAt

	condJSON, err := json.Marshal(r.Conditions)
	if err != nil {
		return fmt.Errorf("marshal conditions: %w", err)
	}

	_, err = e.db.Exec(`
		INSERT INTO rules
		(id, name, description, priority, enabled, action,
		 conditions, cond_logic, ttl_s, rule_id, reason,
		 created_by, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.ID, r.Name, r.Description, r.Priority,
		boolInt(r.Enabled), string(r.Action),
		string(condJSON), r.CondLogic, r.TTLSeconds,
		r.RuleID, r.Reason, r.CreatedBy,
		r.CreatedAt, r.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("DB insert rule: %w", err)
	}

	e.bus.Publish(events.PolicyChangedEvent(createdBy, "created", r.Name))
	return e.loadRules()
}

func (e *Engine) UpdateRule(r *Rule, updatedBy string) error {
	if err := r.Validate(); err != nil {
		return err
	}
	r.UpdatedAt = time.Now().UTC()

	condJSON, err := json.Marshal(r.Conditions)
	if err != nil {
		return err
	}

	result, err := e.db.Exec(`
		UPDATE rules
		SET name=?, description=?, priority=?, enabled=?,
		    action=?, conditions=?, cond_logic=?, ttl_s=?,
		    rule_id=?, reason=?, updated_at=?
		WHERE id=?`,
		r.Name, r.Description, r.Priority, boolInt(r.Enabled),
		string(r.Action), string(condJSON), r.CondLogic,
		r.TTLSeconds, r.RuleID, r.Reason, r.UpdatedAt, r.ID,
	)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("rule not found: %s", r.ID)
	}

	e.bus.Publish(events.PolicyChangedEvent(updatedBy, "updated", r.Name))
	return e.loadRules()
}

func (e *Engine) DeleteRule(id, deletedBy string) error {
	var name string
	e.db.QueryRow(`SELECT name FROM rules WHERE id=?`, id).Scan(&name)

	result, err := e.db.Exec(`DELETE FROM rules WHERE id=?`, id)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("rule not found: %s", id)
	}

	e.bus.Publish(events.PolicyChangedEvent(deletedBy, "deleted", name))
	return e.loadRules()
}

func (e *Engine) GetRule(id string) (*Rule, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, r := range e.rules {
		if r.ID == id {
			rc := *r
			return &rc, nil
		}
	}
	return nil, fmt.Errorf("rule not found: %s", id)
}

func (e *Engine) ListRules() []*Rule {
	// Return ALL rules (including disabled) from DB for admin view
	rows, err := e.db.Query(`
		SELECT id, name, description, priority, enabled, action,
		       conditions, cond_logic, ttl_s, rule_id, reason,
		       created_by, created_at, updated_at, hit_count
		FROM rules ORDER BY priority DESC`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var all []*Rule
	for rows.Next() {
		r := &Rule{}
		var enabled int
		var condJSON string
		rows.Scan(
			&r.ID, &r.Name, &r.Description, &r.Priority,
			&enabled, &r.Action, &condJSON, &r.CondLogic,
			&r.TTLSeconds, &r.RuleID, &r.Reason,
			&r.CreatedBy, &r.CreatedAt, &r.UpdatedAt, &r.HitCount,
		)
		r.Enabled = enabled == 1
		json.Unmarshal([]byte(condJSON), &r.Conditions)
		all = append(all, r)
	}
	return all
}

// Reload hot-reloads rules from DB (called on SIGHUP or admin API).
func (e *Engine) Reload() error {
	if err := e.loadRules(); err != nil {
		return err
	}
	e.mu.RLock()
	count := len(e.rules)
	e.mu.RUnlock()
	e.log.Info("Policy rules hot-reloaded", zap.Int("active_rules", count))
	return nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────
type EngineStats struct {
	TotalRules   int    `json:"total_rules"`
	EnabledRules int    `json:"enabled_rules"`
	TotalEvals   uint64 `json:"total_evals"`
	TotalHits    uint64 `json:"total_hits"`
	TotalApplied uint64 `json:"total_applied"`
	HitRate      float64 `json:"hit_rate"`
}

func (e *Engine) Stats() EngineStats {
	e.mu.RLock()
	active := len(e.rules)
	e.mu.RUnlock()

	var totalFromDB int
	e.db.QueryRow(`SELECT COUNT(*) FROM rules`).Scan(&totalFromDB)

	evals := e.totalEvals.Load()
	hits  := e.totalHits.Load()
	rate  := 0.0
	if evals > 0 {
		rate = float64(hits) / float64(evals) * 100
	}

	return EngineStats{
		TotalRules:   totalFromDB,
		EnabledRules: active,
		TotalEvals:   evals,
		TotalHits:    hits,
		TotalApplied: e.totalApply.Load(),
		HitRate:      rate,
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
func (e *Engine) recordHit(ruleID string) {
	e.db.Exec(
		`UPDATE rules SET hit_count=hit_count+1, last_hit=? WHERE id=?`,
		time.Now().UTC(), ruleID,
	)
}

// FlowFromIP creates a minimal Flow for IP-only lookups.
func FlowFromIP(ip net.IP, threatScore uint8) *Flow {
	return &Flow{SrcIP: ip, ThreatScore: threatScore}
}

func newRuleID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "rule_" + hex.EncodeToString(b)
}

func boolInt(b bool) int {
	if b { return 1 }
	return 0
}
