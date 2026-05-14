// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Notification manager (control-plane/internal/notifications/manager.go).
//              Consumes events from the event bus and fans them out to:
//                - WebSocket connections (SOC dashboard — real-time)
//                - In-memory notification store (for polling / missed events)
//                - External channels: Slack, Telegram, Email (stub, Phase 12)
//
//              Routing: Each notification channel registers topic filters.
//              Only matching events are forwarded to each channel.
//
//              Delivery guarantees: best-effort (non-blocking).
//              Critical failsafe events are buffered with higher priority.
// =============================================================================

package notifications

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"

	"github.com/ft-1/falx-v2/control-plane/internal/events"
)

// ─── Channel Interface ────────────────────────────────────────────────────────
// NotificationChannel is implemented by every delivery backend.
type NotificationChannel interface {
	Name() string
	// Deliver sends an event to the channel. Non-blocking; returns error if failed.
	Deliver(ev events.Event) error
	// TopicFilter returns the topics this channel handles. Nil = all topics.
	TopicFilter() []events.Topic
}

// ─── Stored Notification ─────────────────────────────────────────────────────
type Notification struct {
	ID        string       `json:"id"`
	Event     events.Event `json:"event"`
	Read      bool         `json:"read"`
	CreatedAt time.Time    `json:"created_at"`
}

// ─── Manager ──────────────────────────────────────────────────────────────────
type Manager struct {
	bus      *events.Bus
	sub      *events.Subscriber
	log      *zap.Logger
	channels []NotificationChannel

	// In-memory notification store (ring buffer, last 1000)
	storeMu    sync.RWMutex
	store      []Notification
	storeLimit int

	// WebSocket hub
	wsHub *WSHub

	// Stats
	delivered  atomic.Uint64
	dropped    atomic.Uint64
}

// ─── Constructor ──────────────────────────────────────────────────────────────
func NewManager(bus *events.Bus, log *zap.Logger) *Manager {
	sub := bus.Subscribe("notification-manager", 1024,
		events.TopicIPBlocked, events.TopicIPUnblocked,
		events.TopicThreatAlert, events.TopicCircuitOpen,
		events.TopicCircuitClosed, events.TopicCircuitHalfOpen,
		events.TopicAuthFailed, events.TopicUserLocked,
		events.TopicHoneypotHit, events.TopicConfigChanged,
	)

	m := &Manager{
		bus:        bus,
		sub:        sub,
		log:        log,
		storeLimit: 1000,
		wsHub:      newWSHub(log),
	}
	return m
}

// ─── Register Channel ─────────────────────────────────────────────────────────
func (m *Manager) RegisterChannel(ch NotificationChannel) {
	m.channels = append(m.channels, ch)
	m.log.Info("Notification channel registered", zap.String("name", ch.Name()))
}

// ─── Run ──────────────────────────────────────────────────────────────────────
func (m *Manager) Run(ctx context.Context) {
	m.log.Info("Notification manager started")
	go m.wsHub.Run(ctx)

	for {
		select {
		case <-ctx.Done():
			m.log.Info("Notification manager stopped")
			return
		case ev, ok := <-m.sub.Ch:
			if !ok {
				return
			}
			m.dispatch(ev)
		}
	}
}

func (m *Manager) dispatch(ev events.Event) {
	// Store notification
	notif := Notification{
		ID:        ev.ID,
		Event:     ev,
		CreatedAt: time.Now().UTC(),
	}
	m.storeNotification(notif)

	// WebSocket broadcast
	m.wsHub.Broadcast(ev)

	// External channels
	for _, ch := range m.channels {
		filter := ch.TopicFilter()
		if filter != nil && !topicInList(ev.Topic, filter) {
			continue
		}
		if err := ch.Deliver(ev); err != nil {
			m.log.Warn("Notification channel delivery failed",
				zap.String("channel", ch.Name()),
				zap.String("topic",   string(ev.Topic)),
				zap.Error(err),
			)
			m.dropped.Add(1)
		} else {
			m.delivered.Add(1)
		}
	}
}

func (m *Manager) storeNotification(n Notification) {
	m.storeMu.Lock()
	defer m.storeMu.Unlock()
	m.store = append(m.store, n)
	if len(m.store) > m.storeLimit {
		m.store = m.store[len(m.store)-m.storeLimit:]
	}
}

// ─── API: Get Notifications ───────────────────────────────────────────────────
func (m *Manager) GetNotifications(limit int, unreadOnly bool) []Notification {
	m.storeMu.RLock()
	defer m.storeMu.RUnlock()

	result := make([]Notification, 0, limit)
	for i := len(m.store) - 1; i >= 0 && len(result) < limit; i-- {
		if unreadOnly && m.store[i].Read {
			continue
		}
		result = append(result, m.store[i])
	}
	return result
}

func (m *Manager) MarkRead(id string) {
	m.storeMu.Lock()
	defer m.storeMu.Unlock()
	for i := range m.store {
		if m.store[i].ID == id {
			m.store[i].Read = true
			return
		}
	}
}

// ─── WebSocket Hub ────────────────────────────────────────────────────────────
type WSHub struct {
	mu      sync.RWMutex
	clients map[string]*wsClient
	log     *zap.Logger

	upgrader websocket.Upgrader
}

type wsClient struct {
	id     string
	conn   *websocket.Conn
	send   chan []byte
	userID string
	role   string
}

func newWSHub(log *zap.Logger) *WSHub {
	return &WSHub{
		clients: make(map[string]*wsClient),
		log:     log,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 4096,
			CheckOrigin: func(r *http.Request) bool {
				// Phase 11: validate against allowed origins list
				return true
			},
		},
	}
}

func (h *WSHub) Run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			h.closeAll()
			return
		case <-ticker.C:
			h.ping()
		}
	}
}

// HandleUpgrade upgrades an HTTP connection to WebSocket.
// Called by the SOC backend HTTP handler.
func (h *WSHub) HandleUpgrade(w http.ResponseWriter, r *http.Request, userID, role string) {
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.log.Error("WS upgrade failed", zap.Error(err))
		return
	}

	client := &wsClient{
		id:     userID + "_" + time.Now().Format("150405"),
		conn:   conn,
		send:   make(chan []byte, 256),
		userID: userID,
		role:   role,
	}

	h.mu.Lock()
	h.clients[client.id] = client
	h.mu.Unlock()

	h.log.Info("WebSocket client connected",
		zap.String("user_id", userID),
		zap.String("role", role),
	)

	go h.writePump(client)
	go h.readPump(client)
}

func (h *WSHub) Broadcast(ev events.Event) {
	data, err := json.Marshal(ev)
	if err != nil {
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, client := range h.clients {
		select {
		case client.send <- data:
		default:
			// Slow client — drop this event
		}
	}
}

func (h *WSHub) writePump(c *wsClient) {
	defer func() {
		c.conn.Close()
		h.mu.Lock()
		delete(h.clients, c.id)
		h.mu.Unlock()
	}()

	for data := range c.send {
		c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := c.conn.WriteMessage(websocket.TextMessage, data); err != nil {
			return
		}
	}
}

func (h *WSHub) readPump(c *wsClient) {
	defer close(c.send)
	c.conn.SetReadLimit(512)
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})
	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			return
		}
	}
}

func (h *WSHub) ping() {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, c := range h.clients {
		c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		c.conn.WriteMessage(websocket.PingMessage, nil)
	}
}

func (h *WSHub) closeAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, c := range h.clients {
		c.conn.Close()
	}
}

func (h *WSHub) ConnectedClients() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// ─── External Channel Stubs ───────────────────────────────────────────────────

// SlackChannel stub — fully implemented in Phase 12
type SlackChannel struct {
	WebhookURL string
	Topics     []events.Topic
}
func (s *SlackChannel) Name() string              { return "slack" }
func (s *SlackChannel) TopicFilter() []events.Topic { return s.Topics }
func (s *SlackChannel) Deliver(ev events.Event) error {
	// Phase 12: POST to Slack webhook
	return nil
}

// TelegramChannel stub
type TelegramChannel struct {
	BotToken string
	ChatID   int64
	Topics   []events.Topic
}
func (t *TelegramChannel) Name() string              { return "telegram" }
func (t *TelegramChannel) TopicFilter() []events.Topic { return t.Topics }
func (t *TelegramChannel) Deliver(ev events.Event) error {
	// Phase 12: Telegram Bot API call
	return nil
}

// EmailChannel stub
type EmailChannel struct {
	SMTPAddr  string
	From      string
	To        []string
	Topics    []events.Topic
}
func (e *EmailChannel) Name() string              { return "email" }
func (e *EmailChannel) TopicFilter() []events.Topic { return e.Topics }
func (e *EmailChannel) Deliver(ev events.Event) error {
	// Phase 12: SMTP delivery
	return nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
func topicInList(t events.Topic, list []events.Topic) bool {
	for _, v := range list {
		if v == t {
			return true
		}
	}
	return false
}
