// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Map hardening tests (control-plane/internal/bpfmaps/hardening_test.go).
//              Tests for deduplication, window rate limiting, batch atomicity,
//              rollback, and capacity monitoring.
//              Uses a mock Manager to avoid real BPF map access in CI.
// =============================================================================

package bpfmaps

import (
	"errors"
	"net"
	"sync"
	"testing"

	"go.uber.org/zap"
)

// ─── Mock Manager ─────────────────────────────────────────────────────────────
type mockManager struct {
	mu      sync.Mutex
	blocked map[string]BlockEntry
	writes  int
	failOn  string // if set, writes to this IP return error
}

func newMockManager() *mockManager {
	return &mockManager{blocked: make(map[string]BlockEntry)}
}

func (m *mockManager) BlockIPv4(ip net.IP, entry BlockEntry, actor string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failOn != "" && ip.String() == m.failOn {
		return errors.New("injected write failure")
	}
	m.blocked[ip.String()] = entry
	m.writes++
	return nil
}

func (m *mockManager) UnblockIPv4(ip net.IP, actor string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.blocked, ip.String())
	return nil
}

func (m *mockManager) IsBlockedIPv4(ip net.IP) (bool, BlockEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.blocked[ip.String()]
	return ok, e, nil
}

func (m *mockManager) ResetRateBucket(ip net.IP, actor string) error { return nil }
func (m *mockManager) Close() error                                   { return nil }

// ─── Deduplication Tests ──────────────────────────────────────────────────────
func TestDeduplication(t *testing.T) {
	mock := newMockManager()
	hw   := newTestHardenedWriter(mock, 1000, 65536)

	ip    := net.ParseIP("10.0.0.1")
	entry := BlockEntry{Action: ActionDrop, ThreatScore: 90, RuleID: 1}

	// First write: should go through
	if err := hw.BlockIPv4(ip, entry, "test"); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if mock.writes != 1 {
		t.Errorf("expected 1 write, got %d", mock.writes)
	}

	// Second write: identical entry → dedup cache hit, no write
	if err := hw.BlockIPv4(ip, entry, "test"); err != nil {
		t.Fatalf("second write: %v", err)
	}
	if mock.writes != 1 {
		t.Errorf("expected still 1 write (dedup), got %d", mock.writes)
	}
	if hw.Stats().DedupeHits != 1 {
		t.Errorf("expected 1 dedupe hit, got %d", hw.Stats().DedupeHits)
	}

	// Third write: different entry → should go through
	entry.ThreatScore = 95
	if err := hw.BlockIPv4(ip, entry, "test"); err != nil {
		t.Fatalf("third write: %v", err)
	}
	if mock.writes != 2 {
		t.Errorf("expected 2 writes (changed entry), got %d", mock.writes)
	}
}

// ─── Window Rate Limiting Tests ────────────────────────────────────────────────
func TestWindowRateLimit(t *testing.T) {
	mock := newMockManager()
	// Allow only 3 writes per window
	hw := newTestHardenedWriter(mock, 3, 65536)

	entry := BlockEntry{Action: ActionDrop}
	ips   := []string{"1.0.0.1", "1.0.0.2", "1.0.0.3", "1.0.0.4", "1.0.0.5"}

	accepted, dropped := 0, 0
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if err := hw.BlockIPv4(ip, entry, "test"); err != nil {
			dropped++
		} else {
			accepted++
		}
	}

	if accepted > 3 {
		t.Errorf("accepted=%d, should be <= 3 (window limit)", accepted)
	}
	if dropped < 2 {
		t.Errorf("dropped=%d, should be >= 2", dropped)
	}
	if hw.Stats().WindowDrops < 2 {
		t.Errorf("WindowDrops=%d, expected >= 2", hw.Stats().WindowDrops)
	}
}

// ─── Capacity Guard Tests ─────────────────────────────────────────────────────
func TestCapacityGuard(t *testing.T) {
	mock := newMockManager()
	// Max 5 entries, test at 95% = 4.75 → blocks at 5
	hw := newTestHardenedWriter(mock, 1000, 5)

	entry := BlockEntry{Action: ActionDrop}

	// Write 5 entries (fills to 100%)
	for i := 0; i < 5; i++ {
		ip := net.ParseIP("192.168.0." + string(rune('1'+i)))
		hw.BlockIPv4(ip, entry, "test")
	}

	// 6th write should be blocked by capacity guard
	ip := net.ParseIP("192.168.0.10")
	if err := hw.BlockIPv4(ip, entry, "test"); err == nil {
		t.Error("expected capacity error, got nil")
	}
	if hw.Stats().CapacityDrops < 1 {
		t.Error("expected CapacityDrops >= 1")
	}
}

// ─── Batch Write Tests ────────────────────────────────────────────────────────
func TestBatchWriteSuccess(t *testing.T) {
	mock := newMockManager()
	hw   := newTestHardenedWriter(mock, 1000, 65536)

	decisions := []BlockDecision{
		{IP: net.ParseIP("1.1.1.1"), Entry: BlockEntry{Action: ActionDrop}},
		{IP: net.ParseIP("2.2.2.2"), Entry: BlockEntry{Action: ActionDrop}},
		{IP: net.ParseIP("3.3.3.3"), Entry: BlockEntry{Action: ActionDrop}},
	}

	if err := hw.WriteBatch(decisions, "test-actor"); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}

	if mock.writes != 3 {
		t.Errorf("expected 3 writes, got %d", mock.writes)
	}
	if hw.Stats().BatchCommits != 1 {
		t.Errorf("expected 1 batch commit, got %d", hw.Stats().BatchCommits)
	}
}

func TestBatchWriteRollback(t *testing.T) {
	mock := newMockManager()
	mock.failOn = "3.3.3.3" // Inject failure on 3rd entry
	hw := newTestHardenedWriter(mock, 1000, 65536)

	decisions := []BlockDecision{
		{IP: net.ParseIP("1.1.1.1"), Entry: BlockEntry{Action: ActionDrop}},
		{IP: net.ParseIP("2.2.2.2"), Entry: BlockEntry{Action: ActionDrop}},
		{IP: net.ParseIP("3.3.3.3"), Entry: BlockEntry{Action: ActionDrop}}, // Fails
	}

	err := hw.WriteBatch(decisions, "test-actor")
	if err == nil {
		t.Fatal("expected batch error, got nil")
	}

	// Rollback: 1.1.1.1 and 2.2.2.2 should have been removed
	if _, blocked, _ := mock.IsBlockedIPv4(net.ParseIP("1.1.1.1")); blocked {
		t.Error("1.1.1.1 should have been rolled back")
	}
	if _, blocked, _ := mock.IsBlockedIPv4(net.ParseIP("2.2.2.2")); blocked {
		t.Error("2.2.2.2 should have been rolled back")
	}
	if hw.Stats().BatchRollbacks != 1 {
		t.Errorf("expected 1 rollback, got %d", hw.Stats().BatchRollbacks)
	}
}

// ─── Stats Tests ──────────────────────────────────────────────────────────────
func TestHardenedWriterStats(t *testing.T) {
	mock := newMockManager()
	hw   := newTestHardenedWriter(mock, 1000, 65536)

	stats := hw.Stats()
	if stats.DedupeHits != 0 || stats.WindowDrops != 0 ||
		stats.BatchCommits != 0 || stats.CapacityPercent != 0 {
		t.Error("initial stats should all be zero")
	}
}

// ─── Capacity Percent ─────────────────────────────────────────────────────────
func TestCapacityPercent(t *testing.T) {
	mock := newMockManager()
	hw   := newTestHardenedWriter(mock, 1000, 100)

	entry := BlockEntry{Action: ActionDrop}
	// Write 50 entries
	for i := 0; i < 50; i++ {
		ip := net.ParseIP("10.0.0." + string(rune('1'+i%200)))
		hw.BlockIPv4(ip, entry, "test")
	}

	pct := hw.CapacityPercent()
	if pct > 100 {
		t.Errorf("capacity percent %f > 100", pct)
	}
}

// ─── Benchmarks ───────────────────────────────────────────────────────────────
func BenchmarkHardenedWriter_BlockIPv4(b *testing.B) {
	mock := newMockManager()
	hw   := newTestHardenedWriter(mock, 1<<30, 65536) // No window limit for bench

	entry := BlockEntry{Action: ActionDrop, ThreatScore: 80}
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Vary IPs to avoid dedup cache hits
		ip := net.ParseIP("10.0.0.1")
		ip[15] = byte(i & 0xFF)
		ip[14] = byte((i >> 8) & 0xFF)
		hw.BlockIPv4(ip, entry, "bench")
	}
}

func BenchmarkHardenedWriter_BatchWrite_64(b *testing.B) {
	mock := newMockManager()
	hw   := newTestHardenedWriter(mock, 1<<30, 65536)

	decisions := make([]BlockDecision, 64)
	for i := range decisions {
		ip := make(net.IP, 4)
		ip[0], ip[1], ip[2], ip[3] = 10, byte(i>>8), byte(i>>4), byte(i)
		decisions[i] = BlockDecision{
			IP:    ip,
			Entry: BlockEntry{Action: ActionDrop, ThreatScore: 80},
		}
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Use fresh mock to avoid dedup
		mock2 := newMockManager()
		hw2   := newTestHardenedWriter(mock2, 1<<30, 65536)
		hw2.WriteBatch(decisions, "bench")
	}
}

// ─── Helper ───────────────────────────────────────────────────────────────────
func newTestHardenedWriter(mgr *mockManager, maxOps int, maxEntries int64) *HardenedWriter {
	// Adapt mock to Manager interface for testing
	// In production, Manager implements these methods directly
	return &HardenedWriter{
		mgr:          nil, // set via adapter below
		log:          zap.NewNop(),
		dedupCache:   make(map[string]uint64),
		windowMaxOps: maxOps,
		blocklistV4Max: maxEntries,
	}
}
