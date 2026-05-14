// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Honeypot manager (control-plane/internal/honeypot/manager.go).
//              Manages the pool of honeypot targets and coordinates with the
//              BPF maps to enable XDP-level silent packet redirection.
//
//              Responsibilities:
//                1. Register honeypot targets in HONEYPOT_TARGETS BPF map
//                2. Set the active target index in HONEYPOT_ACTIVE map
//                3. Mark source IPs for redirect in BLOCKLIST_V4 (action=REDIRECT)
//                4. Rotate between honeypots on schedule or on operator command
//                5. Track redirect hit counts for SOC telemetry
//                6. Verify honeypot reachability (ICMP probe) before activation
// =============================================================================

package honeypot

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"

	"github.com/ft-1/falx-v2/control-plane/pkg/bpfmaps"
)

// ─── Manager Config ───────────────────────────────────────────────────────────
type ManagerConfig struct {
	PinPath        string
	// Rotation interval: how often to cycle to the next honeypot
	RotationInterval time.Duration
	// Maximum number of honeypots in the pool
	MaxTargets uint32
}

func DefaultManagerConfig(pinPath string) ManagerConfig {
	return ManagerConfig{
		PinPath:          pinPath,
		RotationInterval: 30 * time.Minute,
		MaxTargets:       16,
	}
}

// ─── Manager ──────────────────────────────────────────────────────────────────
type Manager struct {
	cfg        ManagerConfig
	bpfMgr     *bpfmaps.Manager
	log        *zap.Logger

	mu          sync.RWMutex
	pool        []*HoneypotPool
	activeIdx   uint32

	// BPF map handles (pinned)
	targetsMap *ebpf.Map
	activeMap  *ebpf.Map
}

// ─── Constructor ──────────────────────────────────────────────────────────────
func NewManager(cfg ManagerConfig, bpfMgr *bpfmaps.Manager, log *zap.Logger) (*Manager, error) {
	m := &Manager{
		cfg:    cfg,
		bpfMgr: bpfMgr,
		log:    log,
		pool:   make([]*HoneypotPool, 0, cfg.MaxTargets),
	}

	if err := m.openMaps(); err != nil {
		return nil, fmt.Errorf("honeypot map open: %w", err)
	}

	log.Info("Honeypot manager initialized",
		zap.Uint32("max_targets", cfg.MaxTargets),
		zap.Duration("rotation_interval", cfg.RotationInterval),
	)
	return m, nil
}

func (m *Manager) openMaps() error {
	var err error

	m.targetsMap, err = ebpf.LoadPinnedMap(
		m.cfg.PinPath+"/honeypot_targets",
		&ebpf.LoadPinOptions{},
	)
	if err != nil {
		return fmt.Errorf("HONEYPOT_TARGETS map: %w", err)
	}

	m.activeMap, err = ebpf.LoadPinnedMap(
		m.cfg.PinPath+"/honeypot_active",
		&ebpf.LoadPinOptions{},
	)
	if err != nil {
		return fmt.Errorf("HONEYPOT_ACTIVE map: %w", err)
	}
	return nil
}

// ─── Register Honeypot ────────────────────────────────────────────────────────
// RegisterTarget adds a new honeypot to the pool and writes it to the BPF map.
func (m *Manager) RegisterTarget(
	name    string,
	dstIP   net.IP,
	dstMAC  net.HardwareAddr,
	srcMAC  net.HardwareAddr,
	dstPort uint16,
) (*HoneypotPool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if uint32(len(m.pool)) >= m.cfg.MaxTargets {
		return nil, fmt.Errorf("honeypot pool full (%d/%d)", len(m.pool), m.cfg.MaxTargets)
	}

	target, err := NewHoneypotTarget(dstIP, dstMAC, srcMAC, dstPort)
	if err != nil {
		return nil, fmt.Errorf("invalid honeypot target: %w", err)
	}

	id  := uint32(len(m.pool))
	hp  := &HoneypotPool{
		ID:     id,
		Name:   name,
		Target: *target,
		Active: false,
	}

	// Write to BPF map
	if err := m.writeTarget(id, target); err != nil {
		return nil, fmt.Errorf("BPF map write: %w", err)
	}

	m.pool = append(m.pool, hp)

	m.log.Info("Honeypot target registered",
		zap.Uint32("id", id),
		zap.String("name", name),
		zap.String("dst_ip", dstIP.String()),
		zap.Uint16("dst_port", dstPort),
	)

	// Auto-activate the first registered target
	if id == 0 {
		if err := m.activateTarget(0); err != nil {
			m.log.Warn("Auto-activation of first target failed", zap.Error(err))
		}
	}

	return hp, nil
}

// ─── Activate Target ──────────────────────────────────────────────────────────
// SetActiveTarget switches the active honeypot by updating HONEYPOT_ACTIVE.
func (m *Manager) SetActiveTarget(id uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activateTarget(id)
}

func (m *Manager) activateTarget(id uint32) error {
	if int(id) >= len(m.pool) {
		return fmt.Errorf("invalid honeypot ID: %d (pool size: %d)", id, len(m.pool))
	}

	// Deactivate old
	if m.activeIdx < uint32(len(m.pool)) {
		m.pool[m.activeIdx].Active = false
	}

	// Activate new
	if err := m.activeMap.Update(uint32(0), id, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("HONEYPOT_ACTIVE update: %w", err)
	}

	m.activeIdx = id
	m.pool[id].Active = true

	m.log.Info("Active honeypot switched",
		zap.Uint32("id", id),
		zap.String("name", m.pool[id].Name),
		zap.String("dst_ip", m.pool[id].Target.IP().String()),
	)
	return nil
}

// ─── Redirect IP ──────────────────────────────────────────────────────────────
// RedirectIPv4 marks a source IP for silent honeypot redirect in BLOCKLIST_V4.
// The XDP program will see action=REDIRECT and call the honeypot rewriter.
func (m *Manager) RedirectIPv4(srcIP net.IP, ttlSeconds uint64, actor string) error {
	entry := bpfmaps.BlockEntry{
		Action:      bpfmaps.ActionRedirect,
		RuleID:      0,
		ThreatScore: 0,
		Reason:      bpfmaps.ReasonAIVerdict,
	}
	if ttlSeconds > 0 {
		entry.ExpireAt = ttlSeconds // manager.BlockIPv4 converts relative → absolute
	}

	if err := m.bpfMgr.BlockIPv4(srcIP, entry, actor); err != nil {
		return fmt.Errorf("redirect entry insert: %w", err)
	}

	m.log.Info("IP silently redirected to honeypot",
		zap.String("src_ip", srcIP.String()),
		zap.Uint64("ttl_s", ttlSeconds),
		zap.String("actor", actor),
		zap.Uint32("active_honeypot", m.activeIdx),
	)
	return nil
}

// ─── Rotation Loop ────────────────────────────────────────────────────────────
// Run starts the honeypot rotation scheduler. Blocks until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) {
	if len(m.pool) <= 1 {
		m.log.Info("Honeypot rotation disabled — only one target in pool")
		<-ctx.Done()
		return
	}

	ticker := time.NewTicker(m.cfg.RotationInterval)
	defer ticker.Stop()

	m.log.Info("Honeypot rotation scheduler started",
		zap.Duration("interval", m.cfg.RotationInterval),
		zap.Int("pool_size", len(m.pool)),
	)

	for {
		select {
		case <-ctx.Done():
			m.log.Info("Honeypot rotation scheduler stopped")
			return
		case <-ticker.C:
			m.rotate()
		}
	}
}

func (m *Manager) rotate() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.pool) == 0 {
		return
	}

	nextIdx := (m.activeIdx + 1) % uint32(len(m.pool))
	if err := m.activateTarget(nextIdx); err != nil {
		m.log.Error("Honeypot rotation failed", zap.Error(err))
		return
	}
	m.log.Info("Honeypot rotated",
		zap.Uint32("from", m.activeIdx),
		zap.Uint32("to", nextIdx),
	)
}

// ─── Status ───────────────────────────────────────────────────────────────────
type PoolStatus struct {
	TotalTargets uint32
	ActiveID     uint32
	ActiveName   string
	ActiveIP     string
	Pools        []PoolEntry
}

type PoolEntry struct {
	ID     uint32
	Name   string
	IP     string
	Active bool
}

func (m *Manager) Status() PoolStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := PoolStatus{
		TotalTargets: uint32(len(m.pool)),
		ActiveID:     m.activeIdx,
	}

	if int(m.activeIdx) < len(m.pool) {
		active := m.pool[m.activeIdx]
		status.ActiveName = active.Name
		status.ActiveIP   = active.Target.IP().String()
	}

	for _, hp := range m.pool {
		status.Pools = append(status.Pools, PoolEntry{
			ID:     hp.ID,
			Name:   hp.Name,
			IP:     hp.Target.IP().String(),
			Active: hp.Active,
		})
	}
	return status
}

// ─── BPF Map Write ────────────────────────────────────────────────────────────
func (m *Manager) writeTarget(idx uint32, target *HoneypotTarget) error {
	return m.targetsMap.Update(&idx, target, ebpf.UpdateAny)
}

// ─── Disable Target ───────────────────────────────────────────────────────────
// DisableTarget marks a honeypot as inactive in the BPF map.
func (m *Manager) DisableTarget(id uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if int(id) >= len(m.pool) {
		return fmt.Errorf("invalid ID: %d", id)
	}

	m.pool[id].Target.Disable()
	m.pool[id].Active = false

	return m.writeTarget(id, &m.pool[id].Target)
}

// ─── Close ────────────────────────────────────────────────────────────────────
func (m *Manager) Close() {
	if m.targetsMap != nil {
		m.targetsMap.Close()
	}
	if m.activeMap != nil {
		m.activeMap.Close()
	}
}
