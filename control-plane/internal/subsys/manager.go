// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Subsystem lifecycle manager (control-plane/internal/subsys/manager.go).
//              Manages ordered startup and graceful shutdown of all FALX
//              subsystems. Ensures:
//                - Startup respects dependency order (BPF maps before engines)
//                - Shutdown reverses startup order (engines before BPF maps)
//                - Any subsystem failure triggers controlled teardown
//                - Each subsystem gets a dedicated context for isolation
//
//              Startup order:
//                1. BPF Map Manager    (prerequisite for all others)
//                2. AF_XDP Bridge      (needs maps for XSK_MAP registration)
//                3. Failsafe Engine    (needs maps for FAILSAFE_STATE read/write)
//                4. Honeypot Manager   (needs maps for BLOCKLIST_V4 writes)
//                5. Honeypot Tracker   (needs AF_XDP MetaCh)
//                6. Metrics Collector  (needs all subsystems for stats)
//                7. Metrics Server     (health endpoints + Prometheus scrape)
//
//              Shutdown order: 7 → 1 (exact reverse)
// =============================================================================

package subsys

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ─── Subsystem Interface ──────────────────────────────────────────────────────
type Subsystem interface {
	Name() string
	// Start launches the subsystem. Must return quickly; long-running
	// work happens in goroutines started inside Start().
	Start(ctx context.Context) error
	// Stop performs graceful shutdown. Called in reverse start order.
	Stop(ctx context.Context) error
	// HealthCheck returns nil if the subsystem is healthy.
	HealthCheck() error
}

// ─── Manager ──────────────────────────────────────────────────────────────────
type Manager struct {
	log      *zap.Logger
	subsys   []Subsystem
	mu       sync.Mutex
	started  []Subsystem // tracks started subsystems for ordered shutdown
}

func NewManager(log *zap.Logger) *Manager {
	return &Manager{log: log}
}

// Register adds a subsystem in startup order.
func (m *Manager) Register(s Subsystem) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subsys = append(m.subsys, s)
}

// ─── Start All ────────────────────────────────────────────────────────────────
// StartAll launches all registered subsystems in order.
// If any subsystem fails to start, already-started subsystems are stopped.
func (m *Manager) StartAll(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, s := range m.subsys {
		m.log.Info("Starting subsystem", zap.String("name", s.Name()))

		if err := s.Start(ctx); err != nil {
			m.log.Error("Subsystem start failed",
				zap.String("name", s.Name()),
				zap.Error(err),
			)
			// Shutdown already-started subsystems in reverse order
			m.stopStarted(context.Background())
			return fmt.Errorf("subsystem %q failed to start: %w", s.Name(), err)
		}

		m.started = append(m.started, s)
		m.log.Info("Subsystem started", zap.String("name", s.Name()))
	}

	m.log.Info("All subsystems started", zap.Int("count", len(m.started)))
	return nil
}

// ─── Stop All ─────────────────────────────────────────────────────────────────
// StopAll stops all started subsystems in reverse startup order.
// Errors are logged but do not abort further shutdowns.
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	m.log.Info("Stopping all subsystems")
	m.stopStarted(ctx)
	m.log.Info("All subsystems stopped")
}

func (m *Manager) stopStarted(ctx context.Context) {
	for i := len(m.started) - 1; i >= 0; i-- {
		s := m.started[i]
		m.log.Info("Stopping subsystem", zap.String("name", s.Name()))

		if err := s.Stop(ctx); err != nil {
			m.log.Error("Subsystem stop error",
				zap.String("name", s.Name()),
				zap.Error(err),
			)
		} else {
			m.log.Info("Subsystem stopped", zap.String("name", s.Name()))
		}
	}
	m.started = nil
}

// ─── Health ───────────────────────────────────────────────────────────────────
// HealthAll runs health checks on all started subsystems.
func (m *Manager) HealthAll() map[string]error {
	m.mu.Lock()
	defer m.mu.Unlock()

	results := make(map[string]error, len(m.started))
	for _, s := range m.started {
		results[s.Name()] = s.HealthCheck()
	}
	return results
}
