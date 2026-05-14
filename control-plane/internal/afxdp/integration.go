// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Bridge integration (control-plane/internal/afxdp/integration.go).
//              Wires the AF_XDP bridge to the BPF map manager:
//                1. Creates the bridge (UMEM + XDPSocket)
//                2. Registers the XSK fd in XSK_MAP (so XDP redirects here)
//                3. Enables the afxdp_redirect flag in CONFIG map
//                4. Exposes the MetaCh for Phase 9 (AI inference)
//
//              This is the last wire needed for the zero-copy path:
//                XDP sees suspicious packet → XDP_REDIRECT → XSK_MAP → UMEM
//                Bridge reads from UMEM → PacketMeta → AI engine
//                AI engine decides → Manager.BlockIPv4() → future packets dropped
// =============================================================================

package afxdp

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/ft-1/falx-v2/control-plane/internal/bpfmaps"
)

// ─── Integrated Bridge Handle ─────────────────────────────────────────────────
type IntegratedBridge struct {
	Bridge  *Bridge
	Manager *bpfmaps.Manager
	log     *zap.Logger
}

// NewIntegratedBridge creates a bridge and wires it into XSK_MAP.
func NewIntegratedBridge(
	cfg     BridgeConfig,
	mgr     *bpfmaps.Manager,
	log     *zap.Logger,
) (*IntegratedBridge, error) {

	// ── Create AF_XDP bridge ─────────────────────────────────────────────
	bridge, err := NewBridge(cfg, log)
	if err != nil {
		return nil, fmt.Errorf("bridge init: %w", err)
	}

	// ── Register XSK socket in XSK_MAP ───────────────────────────────────
	// This makes the BPF XDP program able to redirect packets to our socket
	if err := mgr.RegisterXSK(cfg.QueueID, bridge.XSKFd()); err != nil {
		bridge.Close()
		return nil, fmt.Errorf("XSK registration: %w", err)
	}

	// ── Enable AF_XDP redirect in CONFIG map ──────────────────────────────
	// Tells the XDP program to start using XDP_REDIRECT for selected traffic
	currentCfg := bpfmaps.FalxMapConfig{
		DefaultAction:    bpfmaps.ActionPass,
		RateLimitEnabled: 1,
		FailsafeEnabled:  1,
		AFXDPRedirect:    1, // ← Enable zero-copy redirect
		RateCapacity:     1_000,
		RateRefillNs:     1_000_000,
	}
	if err := mgr.UpdateConfig(currentCfg, "afxdp-integration"); err != nil {
		bridge.Close()
		return nil, fmt.Errorf("config update (enable afxdp): %w", err)
	}

	log.Info("AF_XDP bridge integrated with BPF maps",
		zap.String("iface", cfg.IfName),
		zap.Uint32("queue_id", cfg.QueueID),
		zap.Int("xsk_fd", bridge.XSKFd()),
	)

	return &IntegratedBridge{
		Bridge:  bridge,
		Manager: mgr,
		log:     log,
	}, nil
}

// Run starts the bridge datapath. Blocks until ctx is cancelled.
func (ib *IntegratedBridge) Run(ctx context.Context) error {
	return ib.Bridge.Run(ctx)
}

// MetaChan returns the channel of parsed packet metadata.
// Consumed by the AI inference goroutine pool (Phase 9).
func (ib *IntegratedBridge) MetaChan() <-chan *PacketMeta {
	return ib.Bridge.MetaCh
}

// Close tears down the bridge and disables XDP redirect.
func (ib *IntegratedBridge) Close() error {
	// Disable AF_XDP redirect before closing socket to avoid
	// the XDP program redirecting to a closed fd
	cfg := bpfmaps.FalxMapConfig{
		DefaultAction:    bpfmaps.ActionPass,
		RateLimitEnabled: 1,
		FailsafeEnabled:  1,
		AFXDPRedirect:    0, // ← Disable redirect first
		RateCapacity:     1_000,
		RateRefillNs:     1_000_000,
	}
	if err := ib.Manager.UpdateConfig(cfg, "afxdp-shutdown"); err != nil {
		ib.log.Warn("Failed to disable AF_XDP redirect in config", zap.Error(err))
	}

	return ib.Bridge.Close()
}

// Snapshot returns bridge stats for monitoring.
func (ib *IntegratedBridge) Snapshot() BridgeSnapshot {
	return ib.Bridge.Snapshot()
}
