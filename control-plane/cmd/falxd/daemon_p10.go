// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Phase 10 daemon extensions (control-plane/cmd/falxd/daemon_p10.go).
//              Extends FalxDaemon with:
//                - Event Bus     (pub/sub backbone across all subsystems)
//                - Policy Engine (dynamic rule CRUD + evaluation + hot-reload)
//                - Notification Manager (WebSocket + Slack/Telegram/Email stubs)
//                - Hardened Writer (atomic batch writes + dedup + capacity guard)
// =============================================================================

package main

import (
	"context"
	"net"
	"time"

	"go.uber.org/zap"

	"github.com/ft-1/falx-v2/control-plane/internal/bpfmaps"
	"github.com/ft-1/falx-v2/control-plane/internal/events"
	"github.com/ft-1/falx-v2/control-plane/internal/notifications"
	"github.com/ft-1/falx-v2/control-plane/internal/policy"
)

// ─── Phase 10 Handles ─────────────────────────────────────────────────────────
type Phase10 struct {
	EventBus       *events.Bus
	PolicyEngine   *policy.Engine
	NotifManager   *notifications.Manager
	HardenedWriter *bpfmaps.HardenedWriter

	cancelFuncs []context.CancelFunc
}

// ─── InitPhase10 ──────────────────────────────────────────────────────────────
func InitPhase10(
	cfg    *FalxConfig,
	bpfMgr *bpfmaps.Manager,
	ctx    context.Context,
	log    *zap.Logger,
) (*Phase10, error) {

	p10 := &Phase10{}

	// ── [1] Event Bus ─────────────────────────────────────────────────────
	p10.EventBus = events.NewBus()
	log.Info("Event bus initialized")

	// ── [2] Hardened Writer ───────────────────────────────────────────────
	p10.HardenedWriter = bpfmaps.NewHardenedWriter(
		bpfMgr,
		1000, // 1000 writes per 100ms → 10k/sec sustained
		int64(cfg.Maps.BlocklistMaxEntries),
		log,
	)

	// Periodic dedup purge + stats log
	purgeCtx, purgeCancel := context.WithCancel(ctx)
	p10.cancelFuncs = append(p10.cancelFuncs, purgeCancel)
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-purgeCtx.Done():
				return
			case <-ticker.C:
				p10.HardenedWriter.PurgeExpiredDedup()
				s := p10.HardenedWriter.Stats()
				log.Info("Hardened writer",
					zap.Uint64("dedupe_hits",    s.DedupeHits),
					zap.Uint64("window_drops",   s.WindowDrops),
					zap.Float64("capacity_pct",  s.CapacityPercent),
					zap.Uint64("batch_commits",  s.BatchCommits),
					zap.Uint64("batch_rollbacks",s.BatchRollbacks),
				)
				if s.CapacityPercent > 80.0 {
					p10.EventBus.Publish(events.MapHardeningEvent(
						"capacity_warning",
						int64(s.CapacityDrops),
					))
				}
			}
		}
	}()
	log.Info("Hardened BPF map writer initialized",
		zap.Int64("max_entries", int64(cfg.Maps.BlocklistMaxEntries)))

	// ── [3] Policy Engine ─────────────────────────────────────────────────
	policyEngine, err := policy.NewEngine(
		"/var/lib/falx/policy.db",
		bpfMgr,
		p10.EventBus,
		log,
	)
	if err != nil {
		log.Warn("Policy engine init failed — dynamic policies disabled",
			zap.Error(err))
	} else {
		p10.PolicyEngine = policyEngine
		log.Info("Policy engine initialized")
	}

	// ── [4] Notification Manager ──────────────────────────────────────────
	notifCfg := notifications.DefaultConfig()
	p10.NotifManager = notifications.BuildManager(notifCfg, p10.EventBus, log)

	notifCtx, notifCancel := context.WithCancel(ctx)
	p10.cancelFuncs = append(p10.cancelFuncs, notifCancel)
	go p10.NotifManager.Run(notifCtx)

	log.Info("Phase 10 subsystems ready",
		zap.Bool("policy",        p10.PolicyEngine != nil),
		zap.Bool("event_bus",     true),
		zap.Bool("notifications", true),
		zap.Bool("hardened_writer", true),
	)
	return p10, nil
}

// ─── Stop ─────────────────────────────────────────────────────────────────────
func (p10 *Phase10) Stop() {
	for i := len(p10.cancelFuncs) - 1; i >= 0; i-- {
		p10.cancelFuncs[i]()
	}
}

// ─── PolicyAwareBlock ─────────────────────────────────────────────────────────
// Unified block entry point: evaluates policy rules, uses hardened writer,
// and publishes the event — all in one call.
func (p10 *Phase10) PolicyAwareBlock(
	srcIP  net.IP,
	score  uint8,
	actor  string,
	reason string,
	ttlS   uint64,
) error {
	if srcIP == nil {
		return nil
	}

	// Try policy engine first
	if p10.PolicyEngine != nil {
		f := &policy.Flow{SrcIP: srcIP, ThreatScore: score}
		if rule := p10.PolicyEngine.Evaluate(f); rule != nil {
			return p10.PolicyEngine.ApplyRule(rule, f, actor)
		}
	}

	// Fallback: hardened writer
	entry := bpfmaps.BlockEntry{
		Action:      bpfmaps.ActionDrop,
		ThreatScore: score,
		ExpireAt:    ttlS,
		Reason:      bpfmaps.ReasonAIVerdict,
	}
	if err := p10.HardenedWriter.BlockIPv4(srcIP, entry, actor); err != nil {
		return err
	}
	p10.EventBus.Publish(events.IPBlockedEvent(srcIP.String(), actor, reason, ttlS))
	return nil
}
