// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: TTL expiry daemon (control-plane/internal/bpfmaps/expiry.go).
//              The XDP program ignores expired entries (checks expire_at on
//              each hit) but does NOT remove them from the map. This daemon
//              runs in the background and sweeps both BLOCKLIST_V4 and
//              BLOCKLIST_V6 to remove entries past their TTL.
//
//              Why not remove in XDP? BPF LRU maps handle their own eviction.
//              We sweep for correctness, not memory pressure. The sweep
//              interval is configurable and defaults to 60 seconds.
// =============================================================================

package bpfmaps

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// ExpiryDaemon scans blocklist maps and removes expired entries.
type ExpiryDaemon struct {
	mgr      *Manager
	interval time.Duration
	log      *zap.Logger
}

func NewExpiryDaemon(mgr *Manager, interval time.Duration, log *zap.Logger) *ExpiryDaemon {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	return &ExpiryDaemon{mgr: mgr, interval: interval, log: log}
}

// Run starts the sweep loop. Blocks until ctx is cancelled.
func (d *ExpiryDaemon) Run(ctx context.Context) {
	d.log.Info("TTL expiry daemon started", zap.Duration("interval", d.interval))
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			d.log.Info("TTL expiry daemon stopping")
			return
		case <-ticker.C:
			d.sweep()
		}
	}
}

func (d *ExpiryDaemon) sweep() {
	now := uint64(time.Now().Unix())
	removed := 0

	// Sweep BLOCKLIST_V4
	if err := d.mgr.sweepBlocklistV4(now, &removed); err != nil {
		d.log.Error("Blocklist V4 sweep failed", zap.Error(err))
	}

	// Sweep BLOCKLIST_V6
	if err := d.mgr.sweepBlocklistV6(now, &removed); err != nil {
		d.log.Error("Blocklist V6 sweep failed", zap.Error(err))
	}

	if removed > 0 {
		d.log.Info("TTL sweep complete", zap.Int("removed_entries", removed))
	}
}
