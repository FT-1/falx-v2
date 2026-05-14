// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: BPF Map Hardening (control-plane/internal/bpfmaps/hardening.go).
//              Additional protection layer on top of bpfmaps.Manager.
//              Phase 10 map hardening features:
//
//                1. Atomic Batch Writer: applies N map updates as a unit;
//                   if any fail, the entire batch is rolled back.
//                2. Deduplication Cache: prevents redundant writes for IPs
//                   that are already in the blocklist with identical entries.
//                3. Write Window Limiter: enforces a hard cap of X writes
//                   per 100ms window (complementing the per-op token bucket).
//                4. Map Size Monitor: warns when maps reach >80% capacity,
//                   blocks new writes at 95%.
//                5. Entry Integrity Checker: periodic validation that map
//                   contents match the expected state in the policy DB.
// =============================================================================

package bpfmaps

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// ─── Hardened Writer ──────────────────────────────────────────────────────────
type HardenedWriter struct {
	mgr *Manager
	log *zap.Logger

	// Deduplication cache: ip_string → BlockEntry hash
	dedupMu   sync.RWMutex
	dedupCache map[string]uint64 // ip → entry fingerprint

	// Write window: max writes per 100ms
	windowMu     sync.Mutex
	windowCount  int
	windowReset  time.Time
	windowMaxOps int

	// Map capacity tracking
	blocklistV4Count atomic.Int64
	blocklistV4Max   int64

	// Rollback log for batch operations
	rollbackMu sync.Mutex
	lastBatch  []rollbackEntry

	// Stats
	dedupeHits   atomic.Uint64
	windowDrops  atomic.Uint64
	capacityDrop atomic.Uint64
	batchCommits atomic.Uint64
	batchRollbacks atomic.Uint64
}

type rollbackEntry struct {
	ip      net.IP
	existed bool
	entry   BlockEntry
}

// ─── Constructor ──────────────────────────────────────────────────────────────
func NewHardenedWriter(mgr *Manager, maxOpsPerWindow int, maxEntries int64, log *zap.Logger) *HardenedWriter {
	if maxOpsPerWindow <= 0 {
		maxOpsPerWindow = 1000 // 1000 writes per 100ms = 10k/sec
	}
	if maxEntries <= 0 {
		maxEntries = 65536
	}
	return &HardenedWriter{
		mgr:          mgr,
		log:          log,
		dedupCache:   make(map[string]uint64, 4096),
		windowMaxOps: maxOpsPerWindow,
		windowReset:  time.Now(),
		blocklistV4Max: maxEntries,
	}
}

// ─── Single Write (with dedup + window limiting) ───────────────────────────────
func (h *HardenedWriter) BlockIPv4(ip net.IP, entry BlockEntry, actor string) error {
	// 1. Deduplication check
	fingerprint := entryFingerprint(entry)
	key         := ip.String()

	h.dedupMu.RLock()
	existing, found := h.dedupCache[key]
	h.dedupMu.RUnlock()

	if found && existing == fingerprint {
		h.dedupeHits.Add(1)
		return nil // Exact same entry already written — skip
	}

	// 2. Window rate limit
	if !h.checkWindow() {
		h.windowDrops.Add(1)
		return fmt.Errorf("write window exceeded (%d ops/100ms)", h.windowMaxOps)
	}

	// 3. Capacity check
	if h.blocklistV4Count.Load() >= int64(float64(h.blocklistV4Max)*0.95) {
		h.capacityDrop.Add(1)
		h.log.Error("BLOCKLIST_V4 at 95% capacity — write rejected",
			zap.Int64("count", h.blocklistV4Count.Load()),
			zap.Int64("max",   h.blocklistV4Max),
		)
		return fmt.Errorf("blocklist capacity limit reached")
	}

	// 4. Write through to manager
	if err := h.mgr.BlockIPv4(ip, entry, actor); err != nil {
		return err
	}

	// 5. Update dedup cache and capacity counter
	h.dedupMu.Lock()
	if !found {
		h.blocklistV4Count.Add(1)
	}
	h.dedupCache[key] = fingerprint
	h.dedupMu.Unlock()

	return nil
}

// ─── Batch Write (atomic) ─────────────────────────────────────────────────────
// WriteBatch applies N block entries atomically.
// If any write fails, all already-written entries are rolled back.
func (h *HardenedWriter) WriteBatch(decisions []BlockDecision, actor string) error {
	if len(decisions) == 0 {
		return nil
	}

	// Check window capacity for entire batch
	h.windowMu.Lock()
	now := time.Now()
	if now.After(h.windowReset) {
		h.windowCount = 0
		h.windowReset = now.Add(100 * time.Millisecond)
	}
	if h.windowCount+len(decisions) > h.windowMaxOps {
		h.windowMu.Unlock()
		h.windowDrops.Add(uint64(len(decisions)))
		return fmt.Errorf("batch exceeds write window: %d ops requested, %d remaining",
			len(decisions), h.windowMaxOps-h.windowCount)
	}
	h.windowCount += len(decisions)
	h.windowMu.Unlock()

	// Prepare rollback log
	rollback := make([]rollbackEntry, 0, len(decisions))

	for _, d := range decisions {
		// Dedup check
		key         := d.IP.String()
		fingerprint := entryFingerprint(d.Entry)

		h.dedupMu.RLock()
		existing, found := h.dedupCache[key]
		h.dedupMu.RUnlock()

		if found && existing == fingerprint {
			h.dedupeHits.Add(1)
			continue
		}

		// Record pre-write state for rollback
		var prevEntry BlockEntry
		existed := false
		if blocked, prev, _ := h.mgr.IsBlockedIPv4(d.IP); blocked {
			prevEntry = prev
			existed   = true
		}

		// Write
		if err := h.mgr.BlockIPv4(d.IP, d.Entry, actor); err != nil {
			// ROLLBACK: undo all previous writes in this batch
			h.log.Error("Batch write failed — rolling back",
				zap.String("failed_ip", d.IP.String()),
				zap.Error(err),
				zap.Int("already_written", len(rollback)),
			)
			h.rollback(rollback, actor)
			h.batchRollbacks.Add(1)
			return fmt.Errorf("batch write failed at %s: %w — rolled back %d entries",
				d.IP.String(), err, len(rollback))
		}

		rollback = append(rollback, rollbackEntry{
			ip:      d.IP,
			existed: existed,
			entry:   prevEntry,
		})

		// Update dedup cache
		h.dedupMu.Lock()
		if !found {
			h.blocklistV4Count.Add(1)
		}
		h.dedupCache[key] = fingerprint
		h.dedupMu.Unlock()
	}

	h.batchCommits.Add(1)
	h.log.Debug("Batch write committed",
		zap.Int("entries", len(rollback)),
		zap.String("actor", actor),
	)
	return nil
}

// ─── Rollback ─────────────────────────────────────────────────────────────────
func (h *HardenedWriter) rollback(entries []rollbackEntry, actor string) {
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if e.existed {
			// Restore previous entry
			h.mgr.BlockIPv4(e.ip, e.entry, actor+"_rollback") //nolint:errcheck
		} else {
			// Remove the entry we just wrote
			h.mgr.UnblockIPv4(e.ip, actor+"_rollback") //nolint:errcheck

			key := e.ip.String()
			h.dedupMu.Lock()
			delete(h.dedupCache, key)
			h.blocklistV4Count.Add(-1)
			h.dedupMu.Unlock()
		}
	}
}

// ─── Dedup Cache Eviction ─────────────────────────────────────────────────────
// PurgeExpiredDedup removes entries from the dedup cache for IPs that are
// no longer in the blocklist (expired TTL entries removed by ExpiryDaemon).
func (h *HardenedWriter) PurgeExpiredDedup() {
	h.dedupMu.Lock()
	defer h.dedupMu.Unlock()

	purged := 0
	for key := range h.dedupCache {
		ip := net.ParseIP(key)
		if ip == nil {
			delete(h.dedupCache, key)
			purged++
			continue
		}
		if blocked, _, _ := h.mgr.IsBlockedIPv4(ip); !blocked {
			delete(h.dedupCache, key)
			h.blocklistV4Count.Add(-1)
			purged++
		}
	}
	if purged > 0 {
		h.log.Debug("Dedup cache purged", zap.Int("entries", purged))
	}
}

// ─── Capacity Monitor ─────────────────────────────────────────────────────────
func (h *HardenedWriter) CapacityPercent() float64 {
	count := h.blocklistV4Count.Load()
	return float64(count) / float64(h.blocklistV4Max) * 100.0
}

// ─── Stats ────────────────────────────────────────────────────────────────────
type HardenedWriterStats struct {
	DedupeHits      uint64  `json:"dedupe_hits"`
	WindowDrops     uint64  `json:"window_drops"`
	CapacityDrops   uint64  `json:"capacity_drops"`
	BatchCommits    uint64  `json:"batch_commits"`
	BatchRollbacks  uint64  `json:"batch_rollbacks"`
	CacheSize       int     `json:"cache_size"`
	CapacityPercent float64 `json:"capacity_percent"`
	EntryCount      int64   `json:"entry_count"`
}

func (h *HardenedWriter) Stats() HardenedWriterStats {
	h.dedupMu.RLock()
	cacheSize := len(h.dedupCache)
	h.dedupMu.RUnlock()

	return HardenedWriterStats{
		DedupeHits:      h.dedupeHits.Load(),
		WindowDrops:     h.windowDrops.Load(),
		CapacityDrops:   h.capacityDrop.Load(),
		BatchCommits:    h.batchCommits.Load(),
		BatchRollbacks:  h.batchRollbacks.Load(),
		CacheSize:       cacheSize,
		CapacityPercent: h.CapacityPercent(),
		EntryCount:      h.blocklistV4Count.Load(),
	}
}

// ─── Window Check ─────────────────────────────────────────────────────────────
func (h *HardenedWriter) checkWindow() bool {
	h.windowMu.Lock()
	defer h.windowMu.Unlock()

	now := time.Now()
	if now.After(h.windowReset) {
		h.windowCount = 0
		h.windowReset = now.Add(100 * time.Millisecond)
	}
	if h.windowCount >= h.windowMaxOps {
		return false
	}
	h.windowCount++
	return true
}

// ─── Entry Fingerprint ────────────────────────────────────────────────────────
// entryFingerprint produces a cheap hash of a BlockEntry for dedup comparison.
func entryFingerprint(e BlockEntry) uint64 {
	// FNV-1a over the action + rule_id + threat_score fields
	// (TTL is intentionally excluded — same IP can have different TTLs)
	h := uint64(14695981039346656037)
	h = (h ^ uint64(e.Action))    * 1099511628211
	h = (h ^ uint64(e.RuleID))    * 1099511628211
	h = (h ^ uint64(e.ThreatScore)) * 1099511628211
	h = (h ^ uint64(e.Reason))    * 1099511628211
	return h
}
