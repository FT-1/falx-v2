// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Metrics HTTP server (control-plane/internal/metrics/server.go).
//              Exposes three endpoints:
//                GET /metrics       → Prometheus text format
//                GET /healthz       → Liveness probe (daemon alive)
//                GET /readyz        → Readiness probe (BPF maps accessible)
//                GET /debug/stats   → JSON snapshot of all subsystems
// =============================================================================

package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// ─── HealthStatus ──────────────────────────────────────────────────────────────
type HealthStatus struct {
	Status    string            `json:"status"`     // "ok" | "degraded" | "down"
	Checks    map[string]string `json:"checks"`
	Uptime    string            `json:"uptime"`
	Version   string            `json:"version"`
	Architect string            `json:"architect"`
	Timestamp time.Time         `json:"timestamp"`
}

// ─── Server ───────────────────────────────────────────────────────────────────
type Server struct {
	addr        string
	log         *zap.Logger
	startTime   time.Time

	// Health check functions (injected by daemon)
	healthChecks map[string]func() error
}

func NewServer(addr string, log *zap.Logger) *Server {
	return &Server{
		addr:         addr,
		log:          log,
		startTime:    time.Now(),
		healthChecks: make(map[string]func() error),
	}
}

// RegisterHealthCheck adds a named liveness check.
func (s *Server) RegisterHealthCheck(name string, fn func() error) {
	s.healthChecks[name] = fn
}

// ─── Run ──────────────────────────────────────────────────────────────────────
func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()

	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/readyz", s.handleReady)
	mux.HandleFunc("/debug/stats", s.handleDebugStats)

	srv := &http.Server{
		Addr:         s.addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	// Shutdown on context cancellation
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
	}()

	s.log.Info("Metrics server listening", zap.String("addr", s.addr))

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("metrics server: %w", err)
	}
	return nil
}

// ─── Handlers ─────────────────────────────────────────────────────────────────
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := HealthStatus{
		Status:    "ok",
		Checks:    make(map[string]string),
		Uptime:    time.Since(s.startTime).Round(time.Second).String(),
		Version:   "0.1.0",
		Architect: "FT-1",
		Timestamp: time.Now().UTC(),
	}

	httpStatus := http.StatusOK
	for name, check := range s.healthChecks {
		if err := check(); err != nil {
			status.Checks[name] = "FAIL: " + err.Error()
			status.Status = "degraded"
			httpStatus = http.StatusServiceUnavailable
		} else {
			status.Checks[name] = "ok"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(status)
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	// Readiness: verify BPF maps are accessible
	for name, check := range s.healthChecks {
		if err := check(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "NOT READY: %s: %v\n", name, err)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "READY")
}

func (s *Server) handleDebugStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"uptime":    time.Since(s.startTime).String(),
		"version":   "0.1.0",
		"architect": "FT-1",
		"timestamp": time.Now().UTC(),
	})
}
