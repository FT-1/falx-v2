// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Internal event bus (control-plane/pkg/events/bus.go).
//              Decoupled pub/sub system connecting all FALX V2 subsystems.
//              Every significant action publishes an event; notification
//              manager and SOC backend subscribe to relevant topics.
//
//              Design:
//                - Topic-based fan-out (each topic has N subscribers)
//                - Async, non-blocking delivery
//                - Subscriber channels are buffered (spikes absorbed)
//                - Dropped events tracked with atomic counter (no lock needed)
// =============================================================================

package events

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// safelySend sends ev to ch without panicking if ch was concurrently closed.
// Returns false when the channel is closed or full.
func safelySend(ch chan Event, ev Event) (sent bool) {
	defer func() {
		if recover() != nil {
			sent = false
		}
	}()
	select {
	case ch <- ev:
		return true
	default:
		return false
	}
}

// ─── Topics ───────────────────────────────────────────────────────────────────
type Topic string

const (
	TopicIPBlocked       Topic = "security.ip.blocked"
	TopicIPUnblocked     Topic = "security.ip.unblocked"
	TopicIPRedirected    Topic = "security.ip.redirected"
	TopicThreatAlert     Topic = "security.threat.alert"
	TopicCircuitOpen     Topic = "failsafe.circuit.open"
	TopicCircuitClosed   Topic = "failsafe.circuit.closed"
	TopicCircuitHalfOpen Topic = "failsafe.circuit.half_open"
	TopicAuthLogin       Topic = "auth.login"
	TopicAuthLogout      Topic = "auth.logout"
	TopicAuthFailed      Topic = "auth.failed"
	TopicUserCreated     Topic = "admin.user.created"
	TopicUserLocked      Topic = "admin.user.locked"
	TopicConfigChanged   Topic = "admin.config.changed"
	TopicPolicyChanged   Topic = "admin.policy.changed"
	TopicHoneypotHit      Topic = "honeypot.session.new"
	TopicSystemHealth     Topic = "system.health"
	TopicMapHardening     Topic = "security.map.hardening"
	TopicMetricsSnapshot  Topic = "metrics.stats.snapshot" // high-frequency: 1/sec, not stored in notification ring
)

// ─── Severity ─────────────────────────────────────────────────────────────────
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityError    Severity = "error"
	SeverityCritical Severity = "critical"
)

// ─── Event ────────────────────────────────────────────────────────────────────
type Event struct {
	ID        string            `json:"id"`
	Topic     Topic             `json:"topic"`
	Timestamp time.Time         `json:"timestamp"`
	Severity  Severity          `json:"severity"`
	Title     string            `json:"title"`
	Message   string            `json:"message"`
	Source    string            `json:"source"`
	ActorID   string            `json:"actor_id,omitempty"`
	Meta      map[string]string `json:"meta,omitempty"`
}

// ─── Subscriber ───────────────────────────────────────────────────────────────
type Subscriber struct {
	ID     string
	Topics []Topic
	Ch     chan Event
	// closed is set atomically before the channel is closed, so Publish can
	// skip this subscriber on the hot path before reaching safelySend.
	closed atomic.Bool
}

// ─── Bus ──────────────────────────────────────────────────────────────────────
type Bus struct {
	mu          sync.RWMutex
	subscribers map[Topic][]*Subscriber
	// dropped counts events lost to full subscriber channels.
	// Accessed with sync/atomic so concurrent Publish calls don't race.
	dropped atomic.Int64
}

func NewBus() *Bus {
	return &Bus{
		subscribers: make(map[Topic][]*Subscriber),
	}
}

// Subscribe registers a subscriber for one or more topics.
func (b *Bus) Subscribe(id string, bufSize int, topics ...Topic) *Subscriber {
	sub := &Subscriber{
		ID:     id,
		Topics: topics,
		Ch:     make(chan Event, bufSize),
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, t := range topics {
		b.subscribers[t] = append(b.subscribers[t], sub)
	}
	return sub
}

// Unsubscribe removes a subscriber and closes its channel.
// Marks the subscriber closed BEFORE removing it from the map so that any
// concurrent Publish that already holds a snapshot of this subscriber will
// skip it via the closed flag and safelySend's recover — preventing a
// send-on-closed-channel panic.
func (b *Bus) Unsubscribe(sub *Subscriber) {
	sub.closed.Store(true) // Must happen before channel close
	b.mu.Lock()
	for _, t := range sub.Topics {
		subs := b.subscribers[t]
		for i, s := range subs {
			if s.ID == sub.ID {
				b.subscribers[t] = append(subs[:i], subs[i+1:]...)
				break
			}
		}
	}
	b.mu.Unlock()
	// Drain buffered events so readers waiting on Ch.close() don't block.
	for len(sub.Ch) > 0 {
		<-sub.Ch
	}
	close(sub.Ch)
}

// Publish emits an event to all subscribers of the topic. Non-blocking.
func (b *Bus) Publish(ev Event) {
	if ev.ID == "" {
		ev.ID = newEventID()
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}

	b.mu.RLock()
	subs := make([]*Subscriber, len(b.subscribers[ev.Topic]))
	copy(subs, b.subscribers[ev.Topic])
	b.mu.RUnlock()

	for _, sub := range subs {
		if sub.closed.Load() {
			continue // Skip already-unsubscribed subscribers on the hot path
		}
		if !safelySend(sub.Ch, ev) {
			b.dropped.Add(1)
		}
	}
}

// DropCount returns the number of events dropped due to full subscriber channels.
// No lock needed — b.dropped is an atomic.Int64.
func (b *Bus) DropCount() int64 {
	return b.dropped.Load()
}

// ─── Event Builders ───────────────────────────────────────────────────────────

func IPBlockedEvent(srcIP, actor, reason string, ttl uint64) Event {
	return Event{
		Topic:    TopicIPBlocked,
		Severity: SeverityWarning,
		Title:    "IP Address Blocked",
		Message:  fmt.Sprintf("IP %s blocked by %s (reason: %s)", srcIP, actor, reason),
		Source:   "bpf-maps",
		ActorID:  actor,
		Meta: map[string]string{
			"src_ip": srcIP,
			"reason": reason,
			"ttl_s":  fmt.Sprintf("%d", ttl),
		},
	}
}

func IPUnblockedEvent(srcIP, actor string) Event {
	return Event{
		Topic:    TopicIPUnblocked,
		Severity: SeverityInfo,
		Title:    "IP Address Unblocked",
		Message:  fmt.Sprintf("IP %s unblocked by %s", srcIP, actor),
		Source:   "bpf-maps",
		ActorID:  actor,
		Meta:     map[string]string{"src_ip": srcIP},
	}
}

func CircuitOpenEvent(pps uint64, reason string) Event {
	return Event{
		Topic:    TopicCircuitOpen,
		Severity: SeverityCritical,
		Title:    "⚠ Circuit Breaker OPENED — DDoS Mode Active",
		Message:  fmt.Sprintf("XDP entered pure-drop mode. AI bypassed. pps=%d reason=%s", pps, reason),
		Source:   "failsafe-engine",
		Meta: map[string]string{
			"pps":    fmt.Sprintf("%d", pps),
			"reason": reason,
		},
	}
}

func CircuitClosedEvent(pps uint64) Event {
	return Event{
		Topic:    TopicCircuitClosed,
		Severity: SeverityInfo,
		Title:    "✓ Circuit Breaker CLOSED — Normal Operation Restored",
		Message:  "AI inference path re-enabled.",
		Source:   "failsafe-engine",
		Meta:     map[string]string{"pps": fmt.Sprintf("%d", pps)},
	}
}

func ThreatAlertEvent(srcIP, threatType, severity string, confidence float64) Event {
	sev := SeverityWarning
	if confidence > 0.9 {
		sev = SeverityCritical
	}
	return Event{
		Topic:    TopicThreatAlert,
		Severity: sev,
		Title:    "Threat Detected: " + threatType,
		Message:  fmt.Sprintf("Suspicious activity from %s (confidence=%.1f%%)", srcIP, confidence*100),
		Source:   "ai-engine",
		Meta: map[string]string{
			"src_ip":      srcIP,
			"threat_type": threatType,
			"confidence":  fmt.Sprintf("%.3f", confidence),
		},
	}
}

func AuthEvent(userID, username, ip string, success bool, action string) Event {
	topic := TopicAuthLogin
	sev   := SeverityInfo
	msg   := fmt.Sprintf("%s %s from %s", username, action, ip)
	if !success {
		topic = TopicAuthFailed
		sev   = SeverityWarning
		msg   = fmt.Sprintf("Failed %s for %s from %s", action, username, ip)
	}
	return Event{
		Topic:    topic,
		Severity: sev,
		Title:    "Authentication: " + action,
		Message:  msg,
		Source:   "auth-service",
		ActorID:  userID,
		Meta:     map[string]string{"username": username, "ip": ip, "success": fmt.Sprintf("%v", success)},
	}
}

func PolicyChangedEvent(actorID, action, ruleName string) Event {
	return Event{
		Topic:    TopicPolicyChanged,
		Severity: SeverityInfo,
		Title:    "Policy Rule " + action,
		Message:  fmt.Sprintf("Rule '%s' was %s", ruleName, action),
		Source:   "policy-engine",
		ActorID:  actorID,
		Meta:     map[string]string{"rule": ruleName, "action": action},
	}
}

func MetricsSnapshotEvent(pps, dropPPS, passPPS, limitedPPS, mbps float64) Event {
	return Event{
		Topic:    TopicMetricsSnapshot,
		Severity: SeverityInfo,
		Title:    "metrics.snapshot",
		Source:   "metrics-streamer",
		Meta: map[string]string{
			"pps":         fmt.Sprintf("%.2f", pps),
			"drop_pps":    fmt.Sprintf("%.2f", dropPPS),
			"pass_pps":    fmt.Sprintf("%.2f", passPPS),
			"limited_pps": fmt.Sprintf("%.2f", limitedPPS),
			"mbps":        fmt.Sprintf("%.4f", mbps),
		},
	}
}

func MapHardeningEvent(opType string, droppedCount int64) Event {
	return Event{
		Topic:    TopicMapHardening,
		Severity: SeverityWarning,
		Title:    "BPF Map Write Rate-Limited",
		Message:  fmt.Sprintf("Map operation '%s' rate-limited. Total dropped: %d", opType, droppedCount),
		Source:   "bpf-maps",
		Meta: map[string]string{
			"op_type":       opType,
			"total_dropped": fmt.Sprintf("%d", droppedCount),
		},
	}
}

func HoneypotSessionEvent(srcIP, honeypotName string) Event {
	return Event{
		Topic:    TopicHoneypotHit,
		Severity: SeverityWarning,
		Title:    "New Honeypot Session",
		Message:  fmt.Sprintf("Attacker %s redirected to honeypot %s", srcIP, honeypotName),
		Source:   "honeypot-tracker",
		Meta:     map[string]string{"src_ip": srcIP, "honeypot": honeypotName},
	}
}

// ─── Helper ───────────────────────────────────────────────────────────────────
func newEventID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
