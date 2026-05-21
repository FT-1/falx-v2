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
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
)

// ─── Manager ──────────────────────────────────────────────────────────────────
type Manager struct {
	pinPath  string
	noCreate bool // when true, only open existing pinned maps — never create
	rl       *MapRateLimiter
	audit    *AuditLogger
	log      *zap.Logger

	// Cached map handles (opened once at startup, reused)
	blocklistV4   *ebpf.Map
	blocklistV6   *ebpf.Map
	rateLimitMap  *ebpf.Map
	xdpStats      *ebpf.Map // cold-path: rate_limited, failsafe_drops, redirected, parse_errors …
	mappedStats   *ebpf.Map // hot-path: rx_packets, rx_bytes, passed, dropped (bump_mapped)
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
	// NoCreate instructs the manager to attach to maps that already exist on
	// the BPF filesystem without ever creating new ones. Use this in the SOC
	// backend so it always reads from the live kernel maps pinned by falxd,
	// not from a fresh empty copy it accidentally races to create at startup.
	NoCreate      bool
}

// ─── Constructor ──────────────────────────────────────────────────────────────
func NewManager(cfg ManagerConfig, log *zap.Logger) (*Manager, error) {
	rl := NewMapRateLimiter(cfg.RLConfig, log)

	audit, err := NewAuditLogger(cfg.AuditLogPath, log)
	if err != nil {
		return nil, fmt.Errorf("audit logger init failed: %w", err)
	}

	m := &Manager{
		pinPath:  cfg.PinPath,
		noCreate: cfg.NoCreate,
		rl:       rl,
		audit:    audit,
		log:      log,
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

// falxMapSpecs defines the BPF map parameters for programmatic creation when
// the ebpf-user loader has not yet run (e.g. first boot, container cold-start).
// Sizes MUST match the ABI verified in types.go init().
var falxMapSpecs = map[string]*ebpf.MapSpec{
	"blocklist_v4":      {Type: ebpf.LRUHash,     KeySize: 4,  ValueSize: 16, MaxEntries: 65536},
	"blocklist_v6":      {Type: ebpf.LRUHash,     KeySize: 16, ValueSize: 16, MaxEntries: 65536},
	"rate_limit":        {Type: ebpf.LRUHash,     KeySize: 4,  ValueSize: 40, MaxEntries: 65536},
	"xdp_stats":         {Type: ebpf.PerCPUArray, KeySize: 4,  ValueSize: 96, MaxEntries: 1},
	// hot-path compact per-CPU accumulator — 6×u64 = 48 bytes (one cache line)
	"mapped_xdp_stats":  {Type: ebpf.PerCPUArray, KeySize: 4,  ValueSize: 48, MaxEntries: 1},
	"failsafe_state":    {Type: ebpf.Array,        KeySize: 4,  ValueSize: 56, MaxEntries: 1},
	"config":            {Type: ebpf.Array,        KeySize: 4,  ValueSize: 32, MaxEntries: 1},
	"xsk_map":           {Type: ebpf.XSKMap,       KeySize: 4,  ValueSize: 4,  MaxEntries: 64},
}

// ensureBPFMount checks /proc/mounts and mounts bpffs at /sys/fs/bpf if absent.
func ensureBPFMount() error {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return fmt.Errorf("cannot read /proc/mounts: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[1] == "/sys/fs/bpf" && fields[2] == "bpf" {
			return nil // already mounted
		}
	}

	if err := os.MkdirAll("/sys/fs/bpf", 0o755); err != nil {
		return fmt.Errorf("mkdir /sys/fs/bpf: %w", err)
	}
	if err := syscall.Mount("bpffs", "/sys/fs/bpf", "bpf", 0, ""); err != nil {
		return fmt.Errorf("mount bpffs: %w", err)
	}
	return nil
}

// openOrCreatePinnedMap tries to load a pinned map; if the pin does not exist
// it creates the map from the falxMapSpecs table and pins it.
func (m *Manager) openOrCreatePinnedMap(name string, target **ebpf.Map) error {
	pinFile := m.pinPath + "/" + name

	mp, err := ebpf.LoadPinnedMap(pinFile, &ebpf.LoadPinOptions{})
	if err == nil {
		*target = mp
		m.log.Debug("Opened existing pinned map", zap.String("map", name))
		return nil
	}

	spec, ok := falxMapSpecs[name]
	if !ok {
		return fmt.Errorf("no map spec defined for %q and pin not found", name)
	}

	mp, err = ebpf.NewMap(spec)
	if err != nil {
		return fmt.Errorf("create BPF map %q: %w", name, err)
	}
	if err := mp.Pin(pinFile); err != nil {
		mp.Close()
		return fmt.Errorf("pin BPF map %q to %s: %w", name, pinFile, err)
	}

	*target = mp
	m.log.Info("Created and pinned new BPF map",
		zap.String("map", name), zap.String("pin", pinFile))
	return nil
}

// initDefaultMapValues writes safe defaults into newly-created Array maps.
// It is a no-op if the maps already carry non-zero state (real kernel values).
func (m *Manager) initDefaultMapValues() {
	var key uint32 = 0

	var state FailsafeState
	if err := m.failsafeState.Lookup(&key, &state); err != nil || state.PPSThreshold == 0 {
		defaultState := FailsafeState{
			PPSThreshold: 500_000,           // 500 kpps default trip threshold
			BPSThreshold: 10_000_000_000,    // 10 Gbps default
		}
		if err := m.failsafeState.Update(&key, &defaultState, ebpf.UpdateAny); err != nil {
			m.log.Warn("initDefaultMapValues: failsafe_state write failed", zap.Error(err))
		}
	}

	var cfg FalxMapConfig
	if err := m.configMap.Lookup(&key, &cfg); err != nil || cfg.DefaultAction == 0 {
		defaultCfg := FalxMapConfig{
			DefaultAction:    ActionPass,
			RateLimitEnabled: 1,
			FailsafeEnabled:  1,
		}
		if err := m.configMap.Update(&key, &defaultCfg, ebpf.UpdateAny); err != nil {
			m.log.Warn("initDefaultMapValues: config write failed", zap.Error(err))
		}
	}
}

// openExistingPinnedMap loads a map that MUST already be pinned by falxd.
// Returns a clear error if the pin is absent — the SOC backend must never
// silently create a shadow map that diverges from the kernel-live data.
func (m *Manager) openExistingPinnedMap(name string, target **ebpf.Map, optional bool) error {
	pinFile := m.pinPath + "/" + name
	mp, err := ebpf.LoadPinnedMap(pinFile, &ebpf.LoadPinOptions{})
	if err != nil {
		if optional {
			m.log.Debug("Optional BPF map not present — skipping",
				zap.String("map", name), zap.String("pin", pinFile))
			return nil
		}
		return fmt.Errorf(
			"BPF map %q not found at %s — is falxd running and have maps been loaded? (%w)",
			name, pinFile, err,
		)
	}
	*target = mp
	m.log.Debug("Attached to existing pinned BPF map",
		zap.String("map", name), zap.String("pin", pinFile))
	return nil
}

// openMaps ensures bpffs is mounted, the pin directory exists, then opens or
// creates each map. Self-heals on a clean node before the kernel loader runs.
func (m *Manager) openMaps() error {
	if err := ensureBPFMount(); err != nil {
		// Non-fatal: bpffs may already be mounted but /proc/mounts unreadable
		// in a restricted container environment.
		m.log.Warn("BPF filesystem mount check failed — continuing", zap.Error(err))
	}

	type mapEntry struct {
		name     string
		target   **ebpf.Map
		optional bool // in NoCreate mode: missing pin is a warning, not a fatal error
	}
	entries := []mapEntry{
		{"blocklist_v4",     &m.blocklistV4,   false},
		{"blocklist_v6",     &m.blocklistV6,   false},
		{"rate_limit",       &m.rateLimitMap,  false},
		{"xdp_stats",        &m.xdpStats,      false},
		// hot-path per-CPU counters: rx_packets, rx_bytes, passed, dropped
		// written by bump_mapped() — must be opened to get live packet counts
		{"mapped_xdp_stats", &m.mappedStats,   false},
		{"failsafe_state",   &m.failsafeState, false},
		{"config",           &m.configMap,     false},
		// xsk_map is optional: AF_XDP bridge is non-fatal if never pinned
		{"xsk_map",          &m.xskMap,        true},
	}

	if m.noCreate {
		// SOC backend path: open existing maps only, never create.
		// No mkdir — the pin directory must already exist (created by falxd).
		for _, e := range entries {
			if err := m.openExistingPinnedMap(e.name, e.target, e.optional); err != nil {
				return err
			}
		}
		return nil
	}

	// falxd path: create-if-missing (self-heal before kernel loader runs).
	if err := os.MkdirAll(m.pinPath, 0o755); err != nil {
		return fmt.Errorf("create BPF pin directory %s: %w", m.pinPath, err)
	}
	for _, e := range entries {
		if err := m.openOrCreatePinnedMap(e.name, e.target); err != nil {
			return err
		}
	}
	m.initDefaultMapValues()
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

// ReadStats merges the hot-path (MAPPED_XDP_STATS) and cold-path (XDP_STATS)
// per-CPU counters into a single XdpStats view.
//
// Why two maps?
//   bump_mapped() writes rx_packets/rx_bytes/passed/dropped on EVERY packet
//   (hot path, inlined, zero branch overhead).
//   bump_stat() writes rate_limited/failsafe_drops/redirected/parse_errors on
//   exception paths only (cold path, slightly heavier).
//
// Merge rule:
//   rx_packets / rx_bytes / passed → MAPPED  (never written to XDP_STATS)
//   dropped                        → MAPPED  (covers blocklist + failsafe drops)
//   rate_limited / failsafe_drops / redirected / parse_errors / *bans → XDP_STATS
func (m *Manager) ReadStats() (XdpStats, error) {
	var key uint32 = StatsIdx

	// ── 1. Aggregate cold-path XDP_STATS across CPUs ─────────────────────────
	var coldPerCPU []XdpStats
	if err := m.xdpStats.Lookup(&key, &coldPerCPU); err != nil {
		return XdpStats{}, fmt.Errorf("xdp_stats lookup failed: %w", err)
	}
	var cold XdpStats
	for _, s := range coldPerCPU {
		cold = cold.Add(s)
	}

	// ── 2. Aggregate hot-path MAPPED_XDP_STATS across CPUs ───────────────────
	var hotPerCPU []MappedXdpStats
	if err := m.mappedStats.Lookup(&key, &hotPerCPU); err != nil {
		return XdpStats{}, fmt.Errorf("mapped_xdp_stats lookup failed: %w", err)
	}
	var hot MappedXdpStats
	for _, s := range hotPerCPU {
		hot = hot.Add(s)
	}

	// ── 3. Merge: hot-path fields override cold-path; extended fields from cold ─
	return XdpStats{
		RxPackets:     hot.RxPackets,   // ALL packets — only in MAPPED
		RxBytes:       hot.RxBytes,     // ALL bytes   — only in MAPPED
		Dropped:       hot.Dropped,     // blocklist + failsafe drops
		RateLimited:   cold.RateLimited,
		Passed:        hot.Passed,      // ALL passed  — only in MAPPED
		Redirected:    cold.Redirected,
		FailsafeDrops: cold.FailsafeDrops,
		ParseErrors:   cold.ParseErrors,
		MapErrors:     cold.MapErrors,
		CoolingBans:   cold.CoolingBans,
		SynFloodBans:  cold.SynFloodBans,
		LastResetNs:   cold.LastResetNs,
	}, nil
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

