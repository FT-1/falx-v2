// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Notifications config (control-plane/internal/notifications/config.go).
//              Defines configuration for all notification channels and
//              provides a factory that builds the notification manager
//              with all configured channels from the TOML config file.
// =============================================================================

package notifications

import (
	"go.uber.org/zap"

	"github.com/ft-1/falx-v2/control-plane/pkg/events"
)

// ─── Config ───────────────────────────────────────────────────────────────────
type Config struct {
	Enabled bool          `toml:"enabled"`
	Slack   SlackConfig   `toml:"slack"`
	Telegram TelegramCfg  `toml:"telegram"`
	Email   EmailConfig   `toml:"email"`
	WebSocket WSConfig    `toml:"websocket"`
}

type SlackConfig struct {
	Enabled    bool     `toml:"enabled"`
	WebhookURL string   `toml:"webhook_url"`
	Topics     []string `toml:"topics"` // Empty = all
}

type TelegramCfg struct {
	Enabled  bool     `toml:"enabled"`
	BotToken string   `toml:"bot_token"`
	ChatID   int64    `toml:"chat_id"`
	Topics   []string `toml:"topics"`
}

type EmailConfig struct {
	Enabled  bool     `toml:"enabled"`
	SMTPAddr string   `toml:"smtp_addr"`
	From     string   `toml:"from"`
	To       []string `toml:"to"`
	Topics   []string `toml:"topics"`
}

type WSConfig struct {
	Enabled bool `toml:"enabled"`
}

func DefaultConfig() Config {
	return Config{
		Enabled: true,
		WebSocket: WSConfig{Enabled: true},
	}
}

// ─── Factory ──────────────────────────────────────────────────────────────────
// BuildManager creates a fully configured notification manager.
func BuildManager(cfg Config, bus *events.Bus, log *zap.Logger) *Manager {
	mgr := NewManager(bus, log)

	if !cfg.Enabled {
		log.Info("Notification system disabled in config")
		return mgr
	}

	// Register Slack channel
	if cfg.Slack.Enabled && cfg.Slack.WebhookURL != "" {
		ch := &SlackChannel{
			WebhookURL: cfg.Slack.WebhookURL,
			Topics:     parseTopics(cfg.Slack.Topics),
		}
		mgr.RegisterChannel(ch)
		log.Info("Slack notification channel enabled")
	}

	// Register Telegram channel
	if cfg.Telegram.Enabled && cfg.Telegram.BotToken != "" {
		ch := &TelegramChannel{
			BotToken: cfg.Telegram.BotToken,
			ChatID:   cfg.Telegram.ChatID,
			Topics:   parseTopics(cfg.Telegram.Topics),
		}
		mgr.RegisterChannel(ch)
		log.Info("Telegram notification channel enabled")
	}

	// Register Email channel
	if cfg.Email.Enabled && cfg.Email.SMTPAddr != "" {
		ch := &EmailChannel{
			SMTPAddr: cfg.Email.SMTPAddr,
			From:     cfg.Email.From,
			To:       cfg.Email.To,
			Topics:   parseTopics(cfg.Email.Topics),
		}
		mgr.RegisterChannel(ch)
		log.Info("Email notification channel enabled",
			zap.String("smtp", cfg.Email.SMTPAddr))
	}

	return mgr
}

// parseTopics converts string slice to Topic slice.
// Empty slice means all topics.
func parseTopics(strs []string) []events.Topic {
	if len(strs) == 0 {
		return nil // nil = all topics
	}
	topics := make([]events.Topic, len(strs))
	for i, s := range strs {
		topics[i] = events.Topic(s)
	}
	return topics
}

// ─── WebSocket Handler (for SOC backend HTTP router) ─────────────────────────
// WSHandler returns the WebSocket upgrade handler for use in the HTTP router.
func (m *Manager) WSHandler() func(w interface{ Header() interface{} }, r interface{}) {
	// Returns the wsHub's HandleUpgrade for wiring into the HTTP router.
	// Called by SOC backend (Phase 11) as:
	//   router.Handle("/ws", notifMgr.WSUpgradeHandler())
	return nil // Fully implemented in Phase 11
}

// WSUpgradeHandler returns the http.HandlerFunc for WebSocket connections.
func (m *Manager) WSUpgradeHandler() func(w interface{}, r interface{}, userID, role string) {
	return func(w interface{}, r interface{}, userID, role string) {
		// Phase 11 wires this into the HTTP router with proper types
	}
}

// Hub returns the WebSocket hub for direct access from SOC backend.
func (m *Manager) Hub() *WSHub {
	return m.wsHub
}
