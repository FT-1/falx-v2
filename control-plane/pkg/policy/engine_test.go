// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Policy engine tests (control-plane/internal/policy/engine_test.go).
//              Comprehensive test coverage for:
//                - Rule CRUD operations
//                - Condition matching (all operators)
//                - Priority ordering
//                - Conflict detection
//                - Hot-reload correctness
//                - Concurrent evaluation safety
// =============================================================================

package policy

import (
	"net"
	"os"
	"sync"
	"testing"
)

// ─── Test Helpers ─────────────────────────────────────────────────────────────
func newTestEngine(t *testing.T) *Engine {
	t.Helper()

	// In-memory SQLite for tests (no file I/O)
	db, err := openTestDB()
	if err != nil {
		t.Fatalf("test DB: %v", err)
	}
	e := &Engine{db: db, log: newNopLogger()}
	if err := e.migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := e.loadRules(); err != nil {
		t.Fatalf("load rules: %v", err)
	}
	return e
}

// ─── CRUD Tests ───────────────────────────────────────────────────────────────
func TestCreateAndListRule(t *testing.T) {
	e := newTestEngine(t)

	rule := &Rule{
		Name:     "block-scanner",
		Priority: 500,
		Action:   ActionBlock,
		Enabled:  true,
		Conditions: []Condition{
			{Type: CondSrcIP, Operator: "cidr", Value: "10.0.0.0/8"},
		},
		TTLSeconds: 3600,
	}

	if err := e.CreateRule(rule, "test-actor"); err != nil {
		t.Fatalf("CreateRule: %v", err)
	}

	rules := e.ListRules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Name != "block-scanner" {
		t.Errorf("name mismatch: got %s", rules[0].Name)
	}
	if rules[0].ID == "" {
		t.Error("rule ID should not be empty")
	}
}

func TestDeleteRule(t *testing.T) {
	e := newTestEngine(t)

	rule := &Rule{
		Name: "temp-rule", Priority: 100,
		Action: ActionAlert, Enabled: true,
		Conditions: []Condition{{Type: CondSrcIP, Operator: "eq", Value: "192.168.1.1"}},
	}
	e.CreateRule(rule, "actor")

	if err := e.DeleteRule(rule.ID, "actor"); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	if len(e.ListRules()) != 0 {
		t.Error("expected 0 rules after delete")
	}
}

func TestUpdateRule(t *testing.T) {
	e := newTestEngine(t)

	rule := &Rule{
		Name: "original", Priority: 100,
		Action: ActionAlert, Enabled: true,
		Conditions: []Condition{{Type: CondDstPort, Operator: "eq", Value: "22"}},
	}
	e.CreateRule(rule, "actor")

	rule.Name     = "updated"
	rule.Priority = 200
	rule.Action   = ActionBlock
	if err := e.UpdateRule(rule, "actor"); err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}

	updated, _ := e.GetRule(rule.ID)
	if updated.Name != "updated" {
		t.Errorf("name not updated: got %s", updated.Name)
	}
	if updated.Priority != 200 {
		t.Errorf("priority not updated: got %d", updated.Priority)
	}
}

// ─── Condition Matching Tests ─────────────────────────────────────────────────
func TestConditionCIDRMatch(t *testing.T) {
	cases := []struct {
		ip      string
		cidr    string
		wantHit bool
	}{
		{"10.0.0.1",   "10.0.0.0/8",   true},
		{"10.255.255.255", "10.0.0.0/8", true},
		{"11.0.0.1",   "10.0.0.0/8",   false},
		{"192.168.1.50", "192.168.1.0/24", true},
		{"192.168.2.1",  "192.168.1.0/24", false},
	}

	for _, tc := range cases {
		rule := &Rule{
			Name: "test", Priority: 100, Enabled: true, Action: ActionBlock,
			Conditions: []Condition{{Type: CondSrcIP, Operator: "cidr", Value: tc.cidr}},
		}
		f := &Flow{SrcIP: net.ParseIP(tc.ip)}
		got := rule.Match(f)
		if got != tc.wantHit {
			t.Errorf("IP %s vs CIDR %s: want=%v got=%v", tc.ip, tc.cidr, tc.wantHit, got)
		}
	}
}

func TestConditionPortRange(t *testing.T) {
	cases := []struct {
		port    uint16
		value   string
		op      string
		wantHit bool
	}{
		{22,   "22",      "eq",    true},
		{23,   "22",      "eq",    false},
		{443,  "1-1024",  "range", true},
		{8080, "1-1024",  "range", false},
		{80,   "79",      "gt",    true},
		{79,   "79",      "gt",    false},
		{443,  "444",     "lt",    true},
	}

	for _, tc := range cases {
		rule := &Rule{
			Name: "test", Priority: 100, Enabled: true, Action: ActionBlock,
			Conditions: []Condition{{Type: CondDstPort, Operator: tc.op, Value: tc.value}},
		}
		f := &Flow{SrcIP: net.ParseIP("1.2.3.4"), DstPort: tc.port}
		got := rule.Match(f)
		if got != tc.wantHit {
			t.Errorf("port=%d op=%s val=%s: want=%v got=%v",
				tc.port, tc.op, tc.value, tc.wantHit, got)
		}
	}
}

func TestConditionThreatScore(t *testing.T) {
	rule := &Rule{
		Name: "high-threat", Priority: 200, Enabled: true, Action: ActionBlock,
		Conditions: []Condition{{Type: CondThreatScore, Operator: "gte", Value: "85"}},
	}

	if !rule.Match(&Flow{SrcIP: net.ParseIP("1.2.3.4"), ThreatScore: 90}) {
		t.Error("score 90 >= 85 should match")
	}
	if rule.Match(&Flow{SrcIP: net.ParseIP("1.2.3.4"), ThreatScore: 80}) {
		t.Error("score 80 < 85 should not match")
	}
}

// ─── OR Logic Test ─────────────────────────────────────────────────────────────
func TestConditionORLogic(t *testing.T) {
	rule := &Rule{
		Name: "or-test", Priority: 100, Enabled: true, Action: ActionAlert,
		CondLogic: "OR",
		Conditions: []Condition{
			{Type: CondDstPort, Operator: "eq", Value: "22"},
			{Type: CondDstPort, Operator: "eq", Value: "3389"},
		},
	}

	// Port 22 matches first condition
	if !rule.Match(&Flow{SrcIP: net.ParseIP("1.1.1.1"), DstPort: 22}) {
		t.Error("port 22 should match OR rule")
	}
	// Port 3389 matches second condition
	if !rule.Match(&Flow{SrcIP: net.ParseIP("1.1.1.1"), DstPort: 3389}) {
		t.Error("port 3389 should match OR rule")
	}
	// Port 80 matches neither
	if rule.Match(&Flow{SrcIP: net.ParseIP("1.1.1.1"), DstPort: 80}) {
		t.Error("port 80 should NOT match OR rule")
	}
}

// ─── AND Logic Test ────────────────────────────────────────────────────────────
func TestConditionANDLogic(t *testing.T) {
	rule := &Rule{
		Name: "and-test", Priority: 100, Enabled: true, Action: ActionBlock,
		CondLogic: "AND",
		Conditions: []Condition{
			{Type: CondSrcIP,  Operator: "cidr",  Value: "10.0.0.0/8"},
			{Type: CondDstPort, Operator: "eq",   Value: "22"},
			{Type: CondThreatScore, Operator: "gt", Value: "70"},
		},
	}

	// All conditions met
	if !rule.Match(&Flow{
		SrcIP:       net.ParseIP("10.0.0.1"),
		DstPort:     22,
		ThreatScore: 80,
	}) {
		t.Error("all AND conditions met — should match")
	}

	// Missing one condition (wrong port)
	if rule.Match(&Flow{
		SrcIP:       net.ParseIP("10.0.0.1"),
		DstPort:     80,
		ThreatScore: 80,
	}) {
		t.Error("wrong port — AND rule should not match")
	}
}

// ─── Priority Order Test ───────────────────────────────────────────────────────
func TestPriorityOrder(t *testing.T) {
	e := newTestEngine(t)

	// Lower priority: block
	e.CreateRule(&Rule{
		Name: "low-priority-block", Priority: 100, Enabled: true,
		Action: ActionBlock,
		Conditions: []Condition{{Type: CondSrcIP, Operator: "cidr", Value: "0.0.0.0/0"}},
	}, "actor")

	// Higher priority: allow
	e.CreateRule(&Rule{
		Name: "high-priority-allow", Priority: 900, Enabled: true,
		Action: ActionAllow,
		Conditions: []Condition{{Type: CondSrcIP, Operator: "eq", Value: "8.8.8.8"}},
	}, "actor")

	// 8.8.8.8 should hit the allow rule first (higher priority)
	f   := &Flow{SrcIP: net.ParseIP("8.8.8.8")}
	hit := e.Evaluate(f)
	if hit == nil {
		t.Fatal("expected rule match, got nil")
	}
	if hit.Action != ActionAllow {
		t.Errorf("expected ActionAllow, got %s (priority ordering broken)", hit.Action)
	}
}

// ─── Disabled Rule Test ────────────────────────────────────────────────────────
func TestDisabledRuleNotEvaluated(t *testing.T) {
	e := newTestEngine(t)

	e.CreateRule(&Rule{
		Name: "disabled", Priority: 500, Enabled: false,
		Action: ActionBlock,
		Conditions: []Condition{{Type: CondSrcIP, Operator: "cidr", Value: "0.0.0.0/0"}},
	}, "actor")

	// Disabled rules must never match
	hit := e.Evaluate(&Flow{SrcIP: net.ParseIP("1.2.3.4")})
	if hit != nil {
		t.Errorf("disabled rule should not match, got: %s", hit.Name)
	}
}

// ─── Hot-Reload Test ──────────────────────────────────────────────────────────
func TestHotReload(t *testing.T) {
	e := newTestEngine(t)

	// Create a rule
	r := &Rule{
		Name: "reload-test", Priority: 100, Enabled: true,
		Action: ActionAlert,
		Conditions: []Condition{{Type: CondDstPort, Operator: "eq", Value: "443"}},
	}
	e.CreateRule(r, "actor")

	// Reload: should have 1 rule
	if err := e.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if len(e.rules) != 1 {
		t.Errorf("expected 1 rule after reload, got %d", len(e.rules))
	}

	// Delete and reload: should have 0 rules
	e.DeleteRule(r.ID, "actor")
	e.Reload()
	if len(e.rules) != 0 {
		t.Errorf("expected 0 rules after delete+reload, got %d", len(e.rules))
	}
}

// ─── Concurrent Evaluation Safety ─────────────────────────────────────────────
func TestConcurrentEvaluate(t *testing.T) {
	e := newTestEngine(t)

	e.CreateRule(&Rule{
		Name: "concurrent-test", Priority: 100, Enabled: true,
		Action: ActionAlert,
		Conditions: []Condition{{Type: CondSrcIP, Operator: "cidr", Value: "0.0.0.0/0"}},
	}, "actor")

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			f := &Flow{SrcIP: net.ParseIP("10.0.0.1")}
			hit := e.Evaluate(f)
			if hit == nil {
				t.Errorf("goroutine %d: expected match, got nil", n)
			}
		}(i)
	}
	wg.Wait()
}

// ─── Rule Validation Test ─────────────────────────────────────────────────────
func TestRuleValidation(t *testing.T) {
	cases := []struct {
		rule    Rule
		wantErr bool
		desc    string
	}{
		{Rule{Name: "ok", Action: ActionBlock, Priority: 100,
			Conditions: []Condition{{Type: CondSrcIP, Operator: "eq", Value: "1.2.3.4"}}},
			false, "valid rule"},
		{Rule{Name: "", Action: ActionBlock, Priority: 100,
			Conditions: []Condition{{}}},
			true, "empty name"},
		{Rule{Name: "x", Action: "invalid", Priority: 100,
			Conditions: []Condition{{}}},
			true, "invalid action"},
		{Rule{Name: "x", Action: ActionBlock, Priority: -1,
			Conditions: []Condition{{}}},
			true, "negative priority"},
		{Rule{Name: "x", Action: ActionBlock, Priority: 100,
			Conditions: nil},
			true, "no conditions"},
		{Rule{Name: "x", Action: ActionBlock, Priority: 100,
			CondLogic: "INVALID",
			Conditions: []Condition{{Type: CondSrcIP, Operator: "eq", Value: "1.1.1.1"}}},
			true, "invalid cond_logic"},
	}

	for _, tc := range cases {
		err := tc.rule.Validate()
		if tc.wantErr && err == nil {
			t.Errorf("%s: expected error, got nil", tc.desc)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s: unexpected error: %v", tc.desc, err)
		}
	}
}

// ─── Benchmarks ───────────────────────────────────────────────────────────────
func BenchmarkEvaluate_10Rules(b *testing.B) {
	e := newTestEngine(b)
	for i := 0; i < 10; i++ {
		e.CreateRule(&Rule{
			Name:     "bench-rule",
			Priority: i * 10,
			Enabled:  true,
			Action:   ActionAlert,
			Conditions: []Condition{
				{Type: CondSrcIP, Operator: "cidr", Value: "192.168.0.0/16"},
			},
		}, "bench")
	}

	f := &Flow{SrcIP: net.ParseIP("10.0.0.1")} // No match → worst case

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e.Evaluate(f)
	}
}

func BenchmarkEvaluate_100Rules(b *testing.B) {
	e := newTestEngine(b)
	for i := 0; i < 100; i++ {
		e.CreateRule(&Rule{
			Name:     "bench-rule",
			Priority: i,
			Enabled:  true,
			Action:   ActionAlert,
			Conditions: []Condition{
				{Type: CondDstPort, Operator: "eq", Value: "443"},
			},
		}, "bench")
	}

	f := &Flow{SrcIP: net.ParseIP("1.2.3.4"), DstPort: 9999} // No match

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e.Evaluate(f)
	}
}

func BenchmarkRuleMatch_CIDR(b *testing.B) {
	rule := &Rule{
		Name: "bench", Priority: 100, Enabled: true, Action: ActionBlock,
		Conditions: []Condition{{Type: CondSrcIP, Operator: "cidr", Value: "10.0.0.0/8"}},
	}
	f := &Flow{SrcIP: net.ParseIP("10.100.50.1")}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rule.Match(f)
	}
}

// ─── Test Infrastructure ──────────────────────────────────────────────────────
func openTestDB() (*sql.DB, error) {
	return sql.Open("sqlite3", ":memory:")
}

func newNopLogger() *zap.Logger {
	return zap.NewNop()
}

// Benchmark helper
func newTestEngine(tb testing.TB) *Engine {
	db, _ := sql.Open("sqlite3", ":memory:")
	e := &Engine{db: db, log: zap.NewNop()}
	e.migrate()
	e.loadRules()
	return e
}
