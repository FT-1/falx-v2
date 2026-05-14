// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Honeypot session tracker (control-plane/internal/honeypot/tracker.go).
//              Listens on the AF_XDP MetaCh for packets that have been
//              redirected (action=REDIRECT in blocklist). Builds session
//              records from flow data and emits detailed telemetry to the
//              SOC backend for threat analysis and actor profiling.
//
//              A "honeypot session" is a sequence of packets from the same
//              5-tuple (src_ip, dst_ip, src_port, dst_port, proto) after
//              the source IP has been marked for redirect.
// =============================================================================

package honeypot

import (
	"context"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/ft-1/falx-v2/control-plane/internal/afxdp"
	"github.com/ft-1/falx-v2/control-plane/pkg/bpfmaps"
)

// ─── Session ──────────────────────────────────────────────────────────────────
type Session struct {
	FlowID    uint64
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8

	FirstSeen  time.Time
	LastSeen   time.Time
	PacketCount uint64
	ByteCount   uint64

	// Captured payload samples (first 64 bytes from each packet)
	PayloadSamples [][]byte

	// Which honeypot received this session
	HoneypotID   uint32
	HoneypotName string
}

// ─── Tracker ──────────────────────────────────────────────────────────────────
type Tracker struct {
	mu       sync.RWMutex
	sessions map[uint64]*Session // keyed by FlowID
	bpfMgr   *bpfmaps.Manager
	log      *zap.Logger

	// Channel for SOC telemetry events
	EventCh chan SessionEvent

	// Max active sessions to track (memory guard)
	maxSessions int

	// Active honeypot name (for attribution)
	activeHoneypotName string
	activeHoneypotID   uint32
}

// ─── Session Event (emitted to SOC) ──────────────────────────────────────────
type SessionEvent struct {
	Type    string   // "new_session", "session_update", "session_expired"
	Session *Session
	At      time.Time
}

// ─── Constructor ──────────────────────────────────────────────────────────────
func NewTracker(bpfMgr *bpfmaps.Manager, log *zap.Logger) *Tracker {
	return &Tracker{
		sessions:    make(map[uint64]*Session, 1024),
		bpfMgr:      bpfMgr,
		log:         log,
		EventCh:     make(chan SessionEvent, 4096),
		maxSessions: 65536,
	}
}

// ─── Run ──────────────────────────────────────────────────────────────────────
// Run processes PacketMeta from the AF_XDP bridge for REDIRECT-marked IPs.
func (t *Tracker) Run(ctx context.Context, metaCh <-chan *afxdp.PacketMeta) {
	t.log.Info("Honeypot session tracker started")

	cleanupTicker := time.NewTicker(60 * time.Second)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			t.log.Info("Session tracker stopped")
			return

		case meta, ok := <-metaCh:
			if !ok {
				return
			}
			t.processMeta(meta)

		case <-cleanupTicker.C:
			t.cleanupExpiredSessions()
		}
	}
}

// ─── Packet Processing ────────────────────────────────────────────────────────
func (t *Tracker) processMeta(meta *afxdp.PacketMeta) {
	if meta.SrcIP == nil {
		return
	}

	// Check if this source IP is marked for redirect
	blocked, entry, err := t.bpfMgr.IsBlockedIPv4(meta.SrcIP)
	if err != nil || !blocked {
		return
	}
	if entry.Action != bpfmaps.ActionRedirect {
		return // Not a redirect — different action type
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.sessions) >= t.maxSessions {
		t.log.Warn("Session tracker at capacity", zap.Int("max", t.maxSessions))
		return
	}

	now := time.Now()

	sess, exists := t.sessions[meta.FlowID]
	if !exists {
		// New session
		sess = &Session{
			FlowID:       meta.FlowID,
			SrcIP:        append(net.IP{}, meta.SrcIP...),
			DstIP:        append(net.IP{}, meta.DstIP...),
			SrcPort:      meta.SrcPort,
			DstPort:      meta.DstPort,
			Protocol:     meta.Protocol,
			FirstSeen:    now,
			HoneypotID:   t.activeHoneypotID,
			HoneypotName: t.activeHoneypotName,
		}
		t.sessions[meta.FlowID] = sess

		t.emit(SessionEvent{
			Type:    "new_session",
			Session: sess,
			At:      now,
		})

		t.log.Info("New honeypot session",
			zap.String("src_ip", meta.SrcIP.String()),
			zap.Uint16("src_port", meta.SrcPort),
			zap.Uint8("proto", meta.Protocol),
			zap.String("honeypot", t.activeHoneypotName),
		)
	}

	// Update session
	sess.LastSeen     = now
	sess.PacketCount++
	sess.ByteCount   += uint64(meta.PktLen)

	// Collect payload samples (up to 16 per session, memory guard)
	if len(sess.PayloadSamples) < 16 && len(meta.PayloadSample) > 0 {
		sample := make([]byte, len(meta.PayloadSample))
		copy(sample, meta.PayloadSample)
		sess.PayloadSamples = append(sess.PayloadSamples, sample)
	}

	// Emit periodic update every 100 packets
	if sess.PacketCount%100 == 0 {
		t.emit(SessionEvent{
			Type:    "session_update",
			Session: sess,
			At:      now,
		})
	}
}

// ─── Session Expiry ───────────────────────────────────────────────────────────
// Remove sessions with no activity for > 5 minutes
func (t *Tracker) cleanupExpiredSessions() {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff  := time.Now().Add(-5 * time.Minute)
	expired := 0

	for id, sess := range t.sessions {
		if sess.LastSeen.Before(cutoff) {
			t.emit(SessionEvent{
				Type:    "session_expired",
				Session: sess,
				At:      time.Now(),
			})
			delete(t.sessions, id)
			expired++
		}
	}

	if expired > 0 {
		t.log.Info("Expired honeypot sessions cleaned up",
			zap.Int("count", expired),
			zap.Int("remaining", len(t.sessions)),
		)
	}
}

// ─── Active Honeypot Update (called by Manager on rotation) ──────────────────
func (t *Tracker) SetActiveHoneypot(id uint32, name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.activeHoneypotID   = id
	t.activeHoneypotName = name
}

// ─── Stats ────────────────────────────────────────────────────────────────────
func (t *Tracker) ActiveSessionCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.sessions)
}

func (t *Tracker) GetSession(flowID uint64) (*Session, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	s, ok := t.sessions[flowID]
	return s, ok
}

// ─── Event Emission ───────────────────────────────────────────────────────────
func (t *Tracker) emit(ev SessionEvent) {
	select {
	case t.EventCh <- ev:
	default:
		// SOC channel full — drop event (non-critical)
	}
}
