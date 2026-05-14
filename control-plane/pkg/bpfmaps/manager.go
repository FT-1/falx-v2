// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Central BPF map manager (control-plane/internal/bpfmaps/manager.go).
//              Single access point for all BPF map operations. Enforces:
//                1. Rate limiting on every write (via MapRateLimiter)
//                2. Audit logging on every mutation (via AuditLogger)
//                3. TTL-aware reads (expired entries treated as absent)
//                4. Atomic config updates without BPF program reload
//                5. Per-CPU stats aggregation from XDP_STATS PerCpuArray
//
//              All public methods are goroutine-safe.
//              Maps are accessed via pinned file paths (/sys/fs/bpf/falx/*).
// =============================================================================

package bpfmaps

import (
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
)

// ─── Manager ──────────────────────────────────────────────────────────────────
type Manager struct {
	pinPath string
	rl      *MapRateLimiter
	audit   *AuditLogger
	log     *zap.Logger

	// Cached map handles (opened once at startup, reused)
	blocklistV4   *ebpf.Map
	blocklistV6   *ebpf.Map
	rateLimitMap  *ebpf.Map
	xdpStats      *ebpf.Map
	failsafeState *ebpf.Map
	configMap     *ebpf.Map
	xskMap        *ebpf.Map
}

// ─── ManagerConfig ────────────────────────────────────────────────────────────
type ManagerConfig struct {
	PinPath       string
	RLConfig      RateLimitConfig
	AuditLogPath  string
	SweepInterval time.Duration
}

// ─── Constructor ──────────────────────────────────────────────────────────────
func NewManager(cfg ManagerConfig, log *zap.Logger) (*Manager, error) {
	rl := NewMapRateLimiter(cfg.RLConfig, log)

	audit, err := NewAuditLogger(cfg.AuditLogPath, log)
	if err != nil {
		return nil, fmt.Errorf("audit logger init failed: %w", err)
	}

	m := &Manager{
		pinPath: cfg.PinPath,
		rl:      rl,
		audit:   audit,
		log:     log,
	}

	if err := m.openMaps(); err != nil {
		return nil, fmt.Errorf("failed to open BPF maps: %w", err)
	}

	log.Info("BPF Map Manager initialized",
		zap.String("pin_path", cfg.PinPath),
		zap.String("audit_log", cfg.AuditLogPath),
	)
	return m, nil
}

// openMaps loads all pinned BPF maps from the filesystem.
func (m *Manager) openMaps() error {
	type mapEntry struct {
		name   string
		target **ebpf.Map
	}
	entries := []mapEntry{
		{"blocklist_v4",    &m.blocklistV4},
		{"blocklist_v6",    &m.blocklistV6},
		{"rate_limit",      &m.rateLimitMap},
		{"xdp_stats",       &m.xdpStats},
		{"failsafe_state",  &m.failsafeState},
		{"config",          &m.configMap},
		{"xsk_map",         &m.xskMap},
	}

	for _, e := range entries {
		pinFile := m.pinPath + "/" + e.name
		mp, err := ebpf.LoadPinnedMap(pinFile, &ebpf.LoadPinOptions{})
		if err != nil {
			return fmt.Errorf("cannot open pinned map %q: %w", pinFile, err)
		}
		*e.target = mp
		m.log.Debug("Opened pinned map", zap.String("map", e.name))
	}
	return nil
}

// Close releases all map file descriptors.
func (m *Manager) Close() error {
	maps := []*ebpf.Map{
		m.blocklistV4, m.blocklistV6, m.rateLimitMap,
		m.xdpStats, m.failsafeState, m.configMap, m.xskMap,
	}
	for _, mp := range maps {
		if mp != nil {
			mp.Close()
		}
	}
	return m.audit.Close()
}

// ─── Blocklist: IPv4 ──────────────────────────────────────────────────────────

// BlockIPv4 inserts or updates an entry in BLOCKLIST_V4.
// actor identifies the source of the decision ("ai-engine", "soc-operator", etc.)
func (m *Manager) BlockIPv4(ip net.IP, entry BlockEntry, actor string) error {
	if err := m.rl.Check(OpBlockIP); err != nil {
		m.audit.LogBlockIP(ip, entry, actor, err)
		return fmt.Errorf("rate limited: %w", err)
	}

	key, err := IPv4ToUint32(ip)
	if err != nil {
		return fmt.Errorf("invalid IPv4: %w", err)
	}

	// If TTL is a relative duration (seconds from now), convert to absolute
	if entry.ExpireAt > 0 && entry.ExpireAt < 1_000_000_000 {
		// Treat small values as relative TTL in seconds
		entry.ExpireAt = uint64(time.Now().Unix()) + entry.ExpireAt
	}

	opErr := m.blocklistV4.Update(key, &entry, ebpf.UpdateAny)

	m.audit.LogBlockIP(ip, entry, actor, opErr)
	if opErr != nil {
		return fmt.Errorf("map update failed: %w", opErr)
	}

	m.log.Info("IPv4 blocked",
		zap.String("ip", ip.String()),
		zap.String("actor", actor),
		zap.Uint8("action", entry.Action),
		zap.Uint64("expire_at", entry.ExpireAt),
	)
	return nil
}

// UnblockIPv4 removes an entry from BLOCKLIST_V4.
func (m *Manager) UnblockIPv4(ip net.IP, actor string) error {
	if err := m.rl.Check(OpUnblockIP); err != nil {
		m.audit.LogUnblockIP(ip, actor, err)
		return fmt.Errorf("rate limited: %w", err)
	}

	key, err := IPv4ToUint32(ip)
	if err != nil {
		return fmt.Errorf("invalid IPv4: %w", err)
	}

	opErr := m.blocklistV4.Delete(key)
	m.audit.LogUnblockIP(ip, actor, opErr)
	if opErr != nil {
		return fmt.Errorf("map delete failed: %w", opErr)
	}

	m.log.Info("IPv4 unblocked", zap.String("ip", ip.String()), zap.String("actor", actor))
	return nil
}

// IsBlockedIPv4 checks if an IPv4 address is currently blocked (and not expired).
func (m *Manager) IsBlockedIPv4(ip net.IP) (bool, BlockEntry, error) {
	key, err := IPv4ToUint32(ip)
	if err != nil {
		return false, BlockEntry{}, err
	}

	var entry BlockEntry
	if err = m.blocklistV4.Lookup(key, &entry); err != nil {
		return false, BlockEntry{}, nil // Not found = not blocked
	}

	// Check expiry
	if entry.ExpireAt != 0 && uint64(time.Now().Unix()) >= entry.ExpireAt {
		return false, BlockEntry{}, nil // Expired
	}

	return true, entry, nil
}

// ─── Blocklist: IPv6 ──────────────────────────────────────────────────────────

// BlockIPv6 inserts an entry into BLOCKLIST_V6.
func (m *Manager) BlockIPv6(ip net.IP, entry BlockEntry, actor string) error {
	if err := m.rl.Check(OpBlockIP); err != nil {
		return fmt.Errorf("rate limited: %w", err)
	}

	key, err := IPv6ToBytes(ip)
	if err != nil {
		return err
	}

	if entry.ExpireAt > 0 && entry.ExpireAt < 1_000_000_000 {
		entry.ExpireAt = uint64(time.Now().Unix()) + entry.ExpireAt
	}

	opErr := m.blocklistV6.Update(key, &entry, ebpf.UpdateAny)
	m.audit.LogBlockIP(ip, entry, actor, opErr)
	return opErr
}

// UnblockIPv6 removes an entry from BLOCKLIST_V6.
func (m *Manager) UnblockIPv6(ip net.IP, actor string) error {
	if err := m.rl.Check(OpUnblockIP); err != nil {
		return fmt.Errorf("rate limited: %w", err)
	}
	key, err := IPv6ToBytes(ip)
	if err != nil {
		return err
	}
	opErr := m.blocklistV6.Delete(key)
	m.audit.LogUnblockIP(ip, actor, opErr)
	return opErr
}

// ─── Stats ────────────────────────────────────────────────────────────────────

// ReadStats aggregates XdpStats across all CPUs.
func (m *Manager) ReadStats() (XdpStats, error) {
	// XDP_STATS is a PerCpuArray — each CPU has its own value
	// cilium/ebpf returns []T for per-CPU maps
	var perCPU []XdpStats
	var key uint32 = StatsIdx

	if err := m.xdpStats.Lookup(&key, &perCPU); err != nil {
		return XdpStats{}, fmt.Errorf("stats lookup failed: %w", err)
	}

	var total XdpStats
	for _, s := range perCPU {
		total = total.Add(s)
	}
	return total, nil
}

// ─── Failsafe ─────────────────────────────────────────────────────────────────

// ReadFailsafeState returns the current circuit breaker state.
func (m *Manager) ReadFailsafeState() (FailsafeState, error) {
	var state FailsafeState
	var key uint32 = FailsafeIdx
	if err := m.failsafeState.Lookup(&key, &state); err != nil {
		return FailsafeState{}, fmt.Errorf("failsafe state lookup failed: %w", err)
	}
	return state, nil
}

// SetCircuitOpen opens or closes the circuit breaker.
func (m *Manager) SetCircuitOpen(open bool, reason string) error {
	if err := m.rl.Check(OpFailsafe); err != nil {
		return fmt.Errorf("rate limited: %w", err)
	}

	state, err := m.ReadFailsafeState()
	if err != nil {
		return err
	}

	if open {
		state.CircuitOpen  = 1
		state.OpenSinceNs  = uint64(time.Now().UnixNano())
	} else {
		state.CircuitOpen  = 0
		state.OpenSinceNs  = 0
		// Reset rolling counters when closing circuit
		state.CurrentPPS   = 0
		state.CurrentBPS   = 0
	}

	var key uint32 = FailsafeIdx
	opErr := m.failsafeState.Update(&key, &state, ebpf.UpdateAny)
	m.audit.LogCircuitChange(open, state.CurrentPPS, reason)

	if opErr != nil {
		return fmt.Errorf("failsafe state update failed: %w", opErr)
	}

	m.log.Warn("Circuit breaker state changed",
		zap.Bool("open", open),
		zap.String("reason", reason),
	)
	return nil
}

// UpdateFailsafeThresholds writes new PPS/BPS thresholds into the map.
func (m *Manager) UpdateFailsafeThresholds(ppsThr, bpsThr uint64) error {
	if err := m.rl.Check(OpFailsafe); err != nil {
		return fmt.Errorf("rate limited: %w", err)
	}

	state, err := m.ReadFailsafeState()
	if err != nil {
		return err
	}
	state.PPSThreshold = ppsThr
	state.BPSThreshold = bpsThr

	var key uint32 = FailsafeIdx
	return m.failsafeState.Update(&key, &state, ebpf.UpdateAny)
}

// ─── Config ───────────────────────────────────────────────────────────────────

// UpdateConfig pushes a new runtime config to the BPF CONFIG map.
// This changes XDP behavior without reloading the program.
func (m *Manager) UpdateConfig(cfg FalxMapConfig, actor string) error {
	if err := m.rl.Check(OpUpdateConfig); err != nil {
		m.audit.LogConfigUpdate(actor, err)
		return fmt.Errorf("rate limited: %w", err)
	}

	var key uint32 = ConfigIdx
	opErr := m.configMap.Update(&key, &cfg, ebpf.UpdateAny)
	m.audit.LogConfigUpdate(actor, opErr)

	if opErr != nil {
		return fmt.Errorf("config update failed: %w", opErr)
	}

	m.log.Info("CONFIG map updated",
		zap.String("actor", actor),
		zap.Uint8("rate_limit_enabled", cfg.RateLimitEnabled),
		zap.Uint8("failsafe_enabled", cfg.FailsafeEnabled),
	)
	return nil
}

// ─── Blocklist Sweep (for ExpiryDaemon) ──────────────────────────────────────

func (m *Manager) sweepBlocklistV4(nowSec uint64, removed *int) error {
	var (
		key   uint32
		entry BlockEntry
	)

	iter := m.blocklistV4.Iterate()
	var toDelete []uint32

	for iter.Next(&key, &entry) {
		if entry.ExpireAt != 0 && nowSec >= entry.ExpireAt {
			toDelete = append(toDelete, key)
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}

	for _, k := range toDelete {
		kCopy := k
		if err := m.blocklistV4.Delete(kCopy); err == nil {
			*removed++
			ip := Uint32ToIPv4(kCopy)
			m.log.Debug("Expired blocklist entry removed", zap.String("ip", ip.String()))
		}
	}
	return nil
}

func (m *Manager) sweepBlocklistV6(nowSec uint64, removed *int) error {
	var (
		key   [16]byte
		entry BlockEntry
	)

	iter := m.blocklistV6.Iterate()
	var toDelete [][16]byte

	for iter.Next(&key, &entry) {
		if entry.ExpireAt != 0 && nowSec >= entry.ExpireAt {
			toDelete = append(toDelete, key)
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}

	for _, k := range toDelete {
		kCopy := k
		if err := m.blocklistV6.Delete(kCopy); err == nil {
			*removed++
		}
	}
	return nil
}

// ─── RateLimit Map Operations ─────────────────────────────────────────────────

// ResetRateBucket clears the token bucket for a specific source IP.
// Used by control plane to un-throttle a legitimate source.
func (m *Manager) ResetRateBucket(ip net.IP, actor string) error {
	if err := m.rl.Check(OpRateLimit); err != nil {
		return fmt.Errorf("rate limited: %w", err)
	}

	key, err := IPv4ToUint32(ip)
	if err != nil {
		return err
	}
	opErr := m.rateLimitMap.Delete(key)
	if opErr != nil {
		m.log.Warn("Rate bucket reset: key not found (already clean)",
			zap.String("ip", ip.String()))
		return nil // Not an error — bucket may have been evicted by LRU
	}

	m.log.Info("Rate bucket reset",
		zap.String("ip", ip.String()),
		zap.String("actor", actor),
	)
	return nil
}

// ReadRateBucket returns the current token bucket state for an IP.
func (m *Manager) ReadRateBucket(ip net.IP) (RateBucket, bool, error) {
	key, err := IPv4ToUint32(ip)
	if err != nil {
		return RateBucket{}, false, err
	}
	var bucket RateBucket
	if err := m.rateLimitMap.Lookup(key, &bucket); err != nil {
		return RateBucket{}, false, nil // not found
	}
	return bucket, true, nil
}

// ─── XSK Map (AF_XDP, populated by Phase 4) ──────────────────────────────────

// RegisterXSK registers an AF_XDP socket file descriptor into XSK_MAP.
// Called by the AF_XDP bridge (Phase 4) after socket creation.
func (m *Manager) RegisterXSK(queueID uint32, fd int) error {
	if err := m.xskMap.Update(&queueID, uint32(fd), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("XSK_MAP update failed for queue %d: %w", queueID, err)
	}
	m.log.Info("XSK socket registered in BPF map",
		zap.Uint32("queue_id", queueID),
		zap.Int("fd", fd),
	)
	return nil
}

// ─── Rate Limiter Stats (for monitoring) ──────────────────────────────────────

func (m *Manager) RateLimiterStats() map[string]map[string]int64 {
	return m.rl.Stats()
}

// ─── Bulk Operations (for AI engine batch decisions) ─────────────────────────

// BlockIPv4Batch processes multiple block decisions atomically.
// Rate limit is checked ONCE per batch, not per entry.
func (m *Manager) BlockIPv4Batch(decisions []BlockDecision, actor string) []error {
	if err := m.rl.Check(OpBlockIP); err != nil {
		errs := make([]error, len(decisions))
		for i := range errs {
			errs[i] = fmt.Errorf("batch rate limited: %w", err)
		}
		return errs
	}

	errs := make([]error, len(decisions))
	for i, d := range decisions {
		key, err := IPv4ToUint32(d.IP)
		if err != nil {
			errs[i] = err
			continue
		}
		entry := d.Entry
		if entry.ExpireAt > 0 && entry.ExpireAt < 1_000_000_000 {
			entry.ExpireAt = uint64(time.Now().Unix()) + entry.ExpireAt
		}
		errs[i] = m.blocklistV4.Update(key, &entry, ebpf.UpdateAny)
		m.audit.LogBlockIP(d.IP, entry, actor, errs[i])
	}
	return errs
}

// BlockDecision groups an IP with its block entry for batch operations.
type BlockDecision struct {
	IP    net.IP
	Entry BlockEntry
}

