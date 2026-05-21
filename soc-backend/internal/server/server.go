// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: SOC HTTP server (soc-backend/internal/server/server.go).
//              Wires all Phase 9-10 subsystems into a unified HTTP API.
//              Route tree with RBAC:
//
//   Public:
//     POST /api/v1/auth/login           → AuthHandler.Login
//     POST /api/v1/auth/refresh         → AuthHandler.RefreshTokens
//
//   Authenticated (all roles):
//     POST /api/v1/auth/logout          → AuthHandler.Logout
//     POST /api/v1/auth/logout-all      → AuthHandler.LogoutAll
//     GET  /api/v1/auth/me              → AuthHandler.Me
//     PUT  /api/v1/auth/me/password     → AuthHandler.ChangePassword
//     GET  /api/v1/auth/roles           → AuthHandler.ListRoles [viewer+] (SEC-FIX-001)
//     GET  /api/v1/dashboard            → DashboardHandler.Overview  [viewer+]
//     GET  /api/v1/dashboard/stats      → DashboardHandler.Stats     [viewer+]
//     GET  /api/v1/dashboard/threats    → DashboardHandler.Threats   [analyst+]
//     GET  /api/v1/notifications        → NotifHandler.List          [viewer+]
//     PUT  /api/v1/notifications/:id/read → NotifHandler.MarkRead    [viewer+]
//     GET  /ws                          → WebSocket upgrade          [viewer+]
//
//   Security (analyst+):
//     GET  /api/v1/security/blocklist   → SecurityHandler.ListBlocked
//     POST /api/v1/security/block       → SecurityHandler.BlockIP    [analyst: temp only]
//     DELETE /api/v1/security/block/:ip → SecurityHandler.UnblockIP  [senior_analyst+]
//     POST /api/v1/security/redirect    → SecurityHandler.RedirectIP [senior_analyst+]
//     GET  /api/v1/security/rate-buckets → SecurityHandler.RateBuckets
//     GET  /api/v1/security/sessions    → SecurityHandler.HoneypotSessions
//     GET  /api/v1/failsafe             → SecurityHandler.FailsafeStatus
//     POST /api/v1/failsafe/open        → SecurityHandler.ForceOpen  [senior_analyst+]
//     POST /api/v1/failsafe/close       → SecurityHandler.ForceClose [senior_analyst+]
//
//   Policy (senior_analyst+):
//     GET/POST /api/v1/policy/rules     → PolicyHandler.*
//     GET/PUT/DELETE /api/v1/policy/rules/:id
//     POST /api/v1/policy/rules/:id/enable|disable
//     POST /api/v1/policy/reload
//     GET  /api/v1/policy/stats
//
//   Admin (admin+):
//     GET/POST /api/v1/users            → AdminHandler.*
//     GET/PUT  /api/v1/users/:id
//     PUT      /api/v1/users/:id/lock|unlock
//     GET      /api/v1/roles
//     GET      /api/v1/audit            → AdminHandler.AuditLog
//     GET/PUT  /api/v1/system/config    → AdminHandler.SystemConfig  [super_admin]
//     POST     /api/v1/system/restart   → AdminHandler.Restart       [super_admin]
//
//   Observability (all roles):
//     GET /healthz
//     GET /readyz
//     GET /metrics  (Prometheus scrape)
// =============================================================================

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"

	authpkg       "github.com/ft-1/falx-v2/control-plane/pkg/auth"
	"github.com/ft-1/falx-v2/control-plane/pkg/bpfmaps"
	"github.com/ft-1/falx-v2/control-plane/pkg/events"
	"github.com/ft-1/falx-v2/control-plane/pkg/notifications"
	"github.com/ft-1/falx-v2/control-plane/pkg/policy"
	"github.com/ft-1/falx-v2/soc-backend/internal/api"
)

// ─── Metrics Ring Buffer ──────────────────────────────────────────────────────
// metricsRingBuffer holds the last 60 JSON-serialised metrics snapshot events.
// New WebSocket connections are seeded with the full snapshot so charts draw
// immediately without waiting for the next 1-second tick.
type metricsRingBuffer struct {
	mu   sync.RWMutex
	buf  [60][]byte
	head int // next write slot (0-59)
	size int // valid entries: 0..60
}

func (rb *metricsRingBuffer) Add(data []byte) {
	rb.mu.Lock()
	cp := make([]byte, len(data))
	copy(cp, data)
	rb.buf[rb.head] = cp
	rb.head = (rb.head + 1) % 60
	if rb.size < 60 {
		rb.size++
	}
	rb.mu.Unlock()
}

// Snapshot returns all stored frames in chronological order (oldest first).
func (rb *metricsRingBuffer) Snapshot() [][]byte {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	if rb.size == 0 {
		return nil
	}
	out := make([][]byte, rb.size)
	start := ((rb.head - rb.size) + 60) % 60
	for i := 0; i < rb.size; i++ {
		out[i] = rb.buf[(start+i)%60]
	}
	return out
}

// ─── Config ───────────────────────────────────────────────────────────────────
type Config struct {
	HTTPAddr       string
	GRPCAddr       string
	CPAddr         string
	DBPath         string
	AuthDBPath     string
	PolicyDBPath   string
	PinPath        string
	JWTPrivPath    string
	JWTPubPath     string
	AllowedOrigins []string
	Dev            bool   // FALX_DEV: fixed admin TOTP + auto-unlock on every startup
}

// ─── Server ───────────────────────────────────────────────────────────────────
type Server struct {
	cfg    *Config
	log    *zap.Logger
	http   *http.Server

	// Subsystems
	authSvc    *authpkg.Service
	authStore  *authpkg.Store
	jwtMgr     *authpkg.JWTManager
	bpfMgr     *bpfmaps.Manager
	policyEng  *policy.Engine
	eventBus   *events.Bus
	notifMgr       *notifications.Manager
	dashH          *api.DashboardHandler    // held for metrics streamer goroutine
	metricsHistory *metricsRingBuffer       // 60-second sliding window for WS seeding
}

// ─── Constructor ──────────────────────────────────────────────────────────────
func New(cfg *Config, log *zap.Logger) (*Server, error) {
	s := &Server{cfg: cfg, log: log, metricsHistory: &metricsRingBuffer{}}
	if err := s.initSubsystems(); err != nil {
		return nil, err
	}
	s.http = &http.Server{
		Addr:         cfg.HTTPAddr,
		Handler:      s.buildRouter(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	return s, nil
}

// ─── Subsystem Initialisation ─────────────────────────────────────────────────
func (s *Server) initSubsystems() error {
	// Auth
	jwtCfg := authpkg.JWTConfig{
		PrivateKeyPath:    s.cfg.JWTPrivPath,
		PublicKeyPath:     s.cfg.JWTPubPath,
		AccessTokenTTL:    15 * time.Minute,
		RefreshTokenTTL:   7 * 24 * time.Hour,
		InactivityTimeout: 25 * time.Minute,
		Issuer:            "falx-v2",
	}
	jwtMgr, err := authpkg.NewJWTManager(jwtCfg)
	if err != nil {
		return err
	}
	s.jwtMgr = jwtMgr

	authStore, err := authpkg.NewStore(
		s.cfg.AuthDBPath, 25*time.Minute, s.log)
	if err != nil {
		return err
	}
	s.authStore  = authStore
	s.authSvc    = authpkg.NewService(authStore, jwtMgr, s.log)

	if s.cfg.Dev {
		if err := authStore.DevModeBootstrap(); err != nil {
			s.log.Warn("[DEV] Bootstrap failed", zap.Error(err))
		} else {
			s.printDevTOTP()
		}
	}

	// BPF Maps
	mgrCfg := bpfmaps.ManagerConfig{
		PinPath:       s.cfg.PinPath,
		RLConfig:      bpfmaps.DefaultRateLimitConfig(),
		AuditLogPath:  "/var/log/falx/audit.jsonl",
		SweepInterval: 60 * time.Second,
		// NoCreate: the SOC backend must never create its own BPF maps.
		// It must always open the maps pinned by falxd/falx-user so that
		// ReadStats() reads from the live kernel map, not a fresh empty copy.
		NoCreate:      true,
	}
	bpfMgr, err := bpfmaps.NewManager(mgrCfg, s.log)
	if err != nil {
		s.log.Warn("BPF map manager unavailable — running in stub mode", zap.Error(err))
	}
	s.bpfMgr = bpfMgr

	// Event Bus + Notifications
	s.eventBus = events.NewBus()
	s.notifMgr = notifications.BuildManager(
		notifications.DefaultConfig(), s.eventBus, s.log)

	// Policy Engine
	if s.bpfMgr != nil {
		policyEng, err := policy.NewEngine(
			s.cfg.PolicyDBPath, s.bpfMgr, s.eventBus, s.log)
		if err != nil {
			s.log.Warn("Policy engine unavailable", zap.Error(err))
		} else {
			s.policyEng = policyEng
		}
	}

	return nil
}

// ─── Router ───────────────────────────────────────────────────────────────────
func (s *Server) buildRouter() http.Handler {
	r := mux.NewRouter()

	// Global middleware
	r.Use(authpkg.SecurityHeaders)
	r.Use(authpkg.RequestLogger(s.log))
	r.Use(authpkg.CORS(s.cfg.AllowedOrigins))

	// ── Handlers ─────────────────────────────────────────────────────────
	authH    := authpkg.NewHandler(s.authSvc, s.log)
	secH     := api.NewSecurityHandler(s.bpfMgr, s.eventBus, s.log)
	s.dashH   = api.NewDashboardHandler(s.bpfMgr, s.policyEng, s.eventBus, s.log)
	dashH    := s.dashH
	notifH   := api.NewNotificationsHandler(s.notifMgr, s.log)
	adminH   := api.NewAdminHandler(s.authSvc, s.authStore, s.log)
	policyH  := policy.NewHandler(s.policyEng, s.log)
	systemH  := api.NewSystemHandler(s.bpfMgr, s.log)

	auth := s.authSvc // middleware shortcut

	// ── Public Routes ─────────────────────────────────────────────────────
	pub := r.PathPrefix("/api/v1/auth").Subrouter()
	pub.HandleFunc("/login",   authH.Login).Methods(http.MethodPost)
	pub.HandleFunc("/refresh", authH.RefreshTokens).Methods(http.MethodPost)
	// SEC-FIX-001: /roles moved to authenticated subrouter — listing all roles
	// and their permissions is internal information that must not be public.
	// OWASP API3:2023 Broken Object Property Level Authorization.

	// ── Auth-only routes (RequireAuth, NO TFA check) ─────────────────────
	// These routes are accessible with a tfa_ok=false token so that a user
	// who just registered (and has never set up TOTP) can complete enrollment
	// without being blocked by RequireTFAVerified.
	authOnly := r.PathPrefix("/api/v1").Subrouter()
	authOnly.Use(auth.RequireAuth)

	authOnly.HandleFunc("/auth/logout",       authH.Logout).Methods(http.MethodPost)
	authOnly.HandleFunc("/auth/logout-all",   authH.LogoutAll).Methods(http.MethodPost)
	authOnly.HandleFunc("/auth/me",           authH.Me).Methods(http.MethodGet)
	authOnly.HandleFunc("/auth/totp/begin",   authH.TOTPBegin).Methods(http.MethodPost)
	authOnly.HandleFunc("/auth/totp/confirm", authH.TOTPConfirm).Methods(http.MethodPost)

	// ── Authenticated + TFA verified: all remaining routes ────────────────
	authed := r.PathPrefix("/api/v1").Subrouter()
	authed.Use(auth.RequireAuth)
	authed.Use(auth.RequireTFAVerified)
	authed.Use(auth.RequireScope(authpkg.ScopeSession))

	authed.HandleFunc("/auth/me/password",   authH.ChangePassword).Methods(http.MethodPut)
	// SEC-FIX-001: /roles requires authentication (viewer+)
	authed.HandleFunc("/auth/roles",         authH.ListRoles).Methods(http.MethodGet)

	// Dashboard — viewer+
	viewerPerm := auth.RequirePermission(authpkg.PermDashboardView)
	authed.Handle("/dashboard",          viewerPerm(http.HandlerFunc(dashH.Overview))).Methods(http.MethodGet)
	authed.Handle("/dashboard/stats",    viewerPerm(http.HandlerFunc(dashH.Stats))).Methods(http.MethodGet)
	authed.Handle("/dashboard/threats",  viewerPerm(http.HandlerFunc(dashH.Threats))).Methods(http.MethodGet)
	authed.Handle("/dashboard/timeline", viewerPerm(http.HandlerFunc(dashH.Timeline))).Methods(http.MethodGet)

	// Notifications — viewer+
	authed.Handle("/notifications",            viewerPerm(http.HandlerFunc(notifH.List))).Methods(http.MethodGet)
	authed.Handle("/notifications/{id}/read",  viewerPerm(http.HandlerFunc(notifH.MarkRead))).Methods(http.MethodPut)
	authed.Handle("/notifications/unread-count", viewerPerm(http.HandlerFunc(notifH.UnreadCount))).Methods(http.MethodGet)

	// System health — viewer+
	authed.Handle("/system/health", viewerPerm(http.HandlerFunc(systemH.Health))).Methods(http.MethodGet)

	// ── Security — analyst+ ───────────────────────────────────────────────
	analystPerm := auth.RequirePermission(authpkg.PermTelemetryRead)
	seniorPerm  := auth.RequirePermission(authpkg.PermIPBlock)

	authed.Handle("/security/blocklist",        analystPerm(http.HandlerFunc(secH.ListBlocked))).Methods(http.MethodGet)
	authed.Handle("/security/block",            auth.RequirePermission(authpkg.PermIPBlockTemp)(http.HandlerFunc(secH.BlockIP))).Methods(http.MethodPost)
	authed.Handle("/security/block/{ip}",       seniorPerm(http.HandlerFunc(secH.UnblockIP))).Methods(http.MethodDelete)
	authed.Handle("/security/redirect",         seniorPerm(http.HandlerFunc(secH.RedirectIP))).Methods(http.MethodPost)
	authed.Handle("/security/rate-buckets",     analystPerm(http.HandlerFunc(secH.RateBuckets))).Methods(http.MethodGet)
	authed.Handle("/security/honeypot/sessions",analystPerm(http.HandlerFunc(secH.HoneypotSessions))).Methods(http.MethodGet)
	authed.Handle("/security/stats",            analystPerm(http.HandlerFunc(secH.SecurityStats))).Methods(http.MethodGet)

	// Failsafe — view: analyst+, control: senior_analyst+
	failsafeViewPerm := auth.RequirePermission(authpkg.PermFailsafeView)
	failsafeCtrlPerm := auth.RequirePermission(authpkg.PermFailsafeControl)
	authed.Handle("/failsafe",       failsafeViewPerm(http.HandlerFunc(secH.FailsafeStatus))).Methods(http.MethodGet)
	authed.Handle("/failsafe/open",  failsafeCtrlPerm(http.HandlerFunc(secH.ForceOpenCircuit))).Methods(http.MethodPost)
	authed.Handle("/failsafe/close", failsafeCtrlPerm(http.HandlerFunc(secH.ForceCloseCircuit))).Methods(http.MethodPost)
	authed.Handle("/failsafe/thresholds", failsafeCtrlPerm(http.HandlerFunc(secH.UpdateThresholds))).Methods(http.MethodPut)

	// ── Policy — senior_analyst+ ──────────────────────────────────────────
	policyRead  := auth.RequirePermission(authpkg.PermPolicyRead)
	policyWrite := auth.RequirePermission(authpkg.PermPolicyCreate)
	policyDel   := auth.RequirePermission(authpkg.PermPolicyDelete)

	authed.Handle("/policy/rules",             policyRead(http.HandlerFunc(policyH.ListRules))).Methods(http.MethodGet)
	authed.Handle("/policy/rules",             policyWrite(http.HandlerFunc(policyH.CreateRule))).Methods(http.MethodPost)
	authed.Handle("/policy/rules/{id}",        policyRead(http.HandlerFunc(policyH.GetRule))).Methods(http.MethodGet)
	authed.Handle("/policy/rules/{id}",        policyWrite(http.HandlerFunc(policyH.UpdateRule))).Methods(http.MethodPut)
	authed.Handle("/policy/rules/{id}",        policyDel(http.HandlerFunc(policyH.DeleteRule))).Methods(http.MethodDelete)
	authed.Handle("/policy/rules/{id}/enable", policyWrite(http.HandlerFunc(policyH.EnableRule))).Methods(http.MethodPost)
	authed.Handle("/policy/rules/{id}/disable",policyWrite(http.HandlerFunc(policyH.DisableRule))).Methods(http.MethodPost)
	authed.Handle("/policy/reload",            policyWrite(http.HandlerFunc(policyH.ReloadRules))).Methods(http.MethodPost)
	authed.Handle("/policy/stats",             policyRead(http.HandlerFunc(policyH.GetStats))).Methods(http.MethodGet)

	// ── Admin — admin+ ────────────────────────────────────────────────────
	adminPerm  := auth.RequirePermission(authpkg.PermUserList)
	adminWrite := auth.RequirePermission(authpkg.PermUserCreate)
	superPerm  := auth.RequireRole(authpkg.RoleSuperAdmin)

	authed.Handle("/users",              adminPerm(http.HandlerFunc(adminH.ListUsers))).Methods(http.MethodGet)
	authed.Handle("/users",              adminWrite(http.HandlerFunc(authH.CreateUser))).Methods(http.MethodPost)
	authed.Handle("/users/{id}",         adminPerm(http.HandlerFunc(authH.GetUser))).Methods(http.MethodGet)
	authed.Handle("/users/{id}/lock",    adminWrite(http.HandlerFunc(authH.LockUser))).Methods(http.MethodPut)
	authed.Handle("/users/{id}/unlock",  adminWrite(http.HandlerFunc(authH.UnlockUser))).Methods(http.MethodPut)
	authed.Handle("/users/{id}/totp",    superPerm(http.HandlerFunc(authH.TOTPDisable))).Methods(http.MethodDelete)
	authed.Handle("/audit",              auth.RequirePermission(authpkg.PermAuditRead)(http.HandlerFunc(authH.GetAuditLog))).Methods(http.MethodGet)
	authed.Handle("/system/config",      superPerm(http.HandlerFunc(systemH.GetConfig))).Methods(http.MethodGet)
	authed.Handle("/system/config",      superPerm(http.HandlerFunc(systemH.UpdateConfig))).Methods(http.MethodPut)
	authed.Handle("/system/metrics-summary", adminPerm(http.HandlerFunc(systemH.MetricsSummary))).Methods(http.MethodGet)

	// ── WebSocket — viewer+ (requires full TFA) ───────────────────────────
	r.Handle("/ws", auth.RequireAuth(auth.RequireTFAVerified(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		claims := authpkg.ClaimsFromContext(req.Context())
		if claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		seed := s.metricsHistory.Snapshot()
		s.notifMgr.Hub().HandleUpgrade(w, req, claims.UserID, string(claims.Role), seed)
	}))))

	// ── Observability (no auth) ───────────────────────────────────────────
	r.HandleFunc("/healthz",  systemH.Liveness).Methods(http.MethodGet)
	r.HandleFunc("/readyz",   systemH.Readiness).Methods(http.MethodGet)

	// ── SPA: Serve dashboard HTML ─────────────────────────────────────────
	r.PathPrefix("/").HandlerFunc(serveDashboard)

	return r
}

// ─── Run / Shutdown ───────────────────────────────────────────────────────────
func (s *Server) Run(ctx context.Context) error {
	go s.notifMgr.Run(ctx)
	go s.runMetricsStreamer(ctx)

	s.log.Info("HTTP server listening", zap.String("addr", s.cfg.HTTPAddr))
	errCh := make(chan error, 1)
	go func() { errCh <- s.http.ListenAndServe() }()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *Server) Shutdown(ctx context.Context) {
	s.log.Info("Shutting down HTTP server")
	s.http.Shutdown(ctx)
	if s.bpfMgr != nil {
		s.bpfMgr.Close()
	}
}

func (s *Server) Reload() {
	if s.policyEng != nil {
		s.policyEng.Reload()
	}
	s.log.Info("Configuration reloaded")
}

// runMetricsStreamer samples BPF counters every second, computes per-second
// rates (delta / elapsed), updates the dashboard handler's rate cache, and
// publishes a metrics.stats.snapshot event to the WebSocket hub so connected
// clients receive live PPS/chart data without waiting for a manual poll.
//
// If falx-soc started before falxd has pinned its maps (s.bpfMgr == nil), the
// streamer polls every 2 seconds until the maps appear, then attaches and starts
// streaming without requiring a restart.
func (s *Server) runMetricsStreamer(ctx context.Context) {
	if s.dashH == nil {
		return
	}

	// Wait for BPF maps to be available (late-attach when falxd starts after us)
	mgr := s.bpfMgr
	if mgr == nil {
		s.log.Info("Metrics streamer: BPF maps not ready, polling until falxd pins them")
		retryTicker := time.NewTicker(2 * time.Second)
		defer retryTicker.Stop()
	waitLoop:
		for {
			select {
			case <-ctx.Done():
				return
			case <-retryTicker.C:
				mgrCfg := bpfmaps.ManagerConfig{
					PinPath:       s.cfg.PinPath,
					RLConfig:      bpfmaps.DefaultRateLimitConfig(),
					AuditLogPath:  "/var/log/falx/audit.jsonl",
					SweepInterval: 60 * time.Second,
					NoCreate:      true,
				}
				newMgr, err := bpfmaps.NewManager(mgrCfg, s.log)
				if err != nil {
					continue
				}
				mgr = newMgr
				s.bpfMgr = mgr
				s.dashH.SetBPFMgr(mgr)
				s.log.Info("Metrics streamer: BPF maps attached (late-attach)")
				break waitLoop
			}
		}
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var (
		prevStats bpfmaps.XdpStats
		prevAt    time.Time
		first     = true
	)

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			stats, err := mgr.ReadStats()
			if err != nil {
				s.log.Warn("Metrics streamer: BPF read failed", zap.Error(err))
				continue
			}

			if first {
				prevStats = stats
				prevAt    = now
				first     = false
				continue
			}

			elapsed := now.Sub(prevAt).Seconds()
			if elapsed <= 0 {
				elapsed = 1
			}

			pps        := float64(stats.RxPackets-prevStats.RxPackets)   / elapsed
			dropPPS    := float64(stats.Dropped-prevStats.Dropped)        / elapsed
			passPPS    := float64(stats.Passed-prevStats.Passed)          / elapsed
			limitedPPS := float64(stats.RateLimited-prevStats.RateLimited)/ elapsed
			rxBytesDelta := stats.RxBytes - prevStats.RxBytes
			mbps        := float64(rxBytesDelta) * 8 / 1_000_000 / elapsed

			// DEBUG: log every 5 seconds so the log doesn't flood but stays readable.
			// Remove once confirmed non-zero values flow to the frontend.
			if int(now.Unix())%5 == 0 {
				s.log.Info("[DEBUG_STATS] BPF counters",
					zap.Uint64("rx_packets",   stats.RxPackets),
					zap.Uint64("passed",       stats.Passed),
					zap.Uint64("dropped",      stats.Dropped),
					zap.Uint64("rate_limited", stats.RateLimited),
					zap.Float64("pps",         pps),
					zap.Float64("pass_pps",    passPPS),
					zap.Float64("drop_pps",    dropPPS),
					zap.Float64("mbps",        mbps),
				)
			}

			// Clamp negatives (counter reset on daemon restart)
			if pps < 0        { pps = 0 }
			if dropPPS < 0    { dropPPS = 0 }
			if passPPS < 0    { passPPS = 0 }
			if limitedPPS < 0 { limitedPPS = 0 }
			if mbps < 0       { mbps = 0 }

			rates := api.MetricsRates{
				PPS:        pps,
				DropPPS:    dropPPS,
				PassPPS:    passPPS,
				LimitedPPS: limitedPPS,
				MBps:       mbps,
				SampledAt:  now.UTC(),
			}
			s.dashH.UpdateRates(rates)

			// Publish to WebSocket clients and store in 60-second ring buffer.
			ev := events.MetricsSnapshotEvent(pps, dropPPS, passPPS, limitedPPS, mbps)
			s.eventBus.Publish(ev)
			if frame, err := json.Marshal(ev); err == nil {
				s.metricsHistory.Add(frame)
			}

			prevStats = stats
			prevAt    = now
		}
	}
}

// printDevTOTP computes the current TOTP code for the fixed dev admin secret and
// prints a visible banner to stderr so developers can copy it straight from the
// terminal after every restart — no external authenticator app needed.
func (s *Server) printDevTOTP() {
	code, err := authpkg.GenerateTOTP(authpkg.DevTOTPSecret, time.Now())
	if err != nil {
		s.log.Warn("[DEV] Failed to compute TOTP code", zap.Error(err))
		return
	}
	remaining := 30 - (time.Now().Unix() % 30)
	fmt.Fprintf(os.Stderr,
		"\n╔══════════════════════════════════════════════════╗\n"+
			"║  [DEV] Admin 2FA Token : %-6s                  ║\n"+
			"║  Valid for next        : %2d seconds             ║\n"+
			"║  Secret                : %-28s  ║\n"+
			"╚══════════════════════════════════════════════════╝\n\n",
		code, remaining, authpkg.DevTOTPSecret,
	)
	s.log.Warn("[DEV] Admin 2FA Token",
		zap.String("code", code),
		zap.Int64("valid_for_seconds", remaining),
		zap.String("secret", authpkg.DevTOTPSecret),
	)
}

// serveDashboard serves the embedded SOC dashboard HTML for all unmatched paths.
func serveDashboard(w http.ResponseWriter, r *http.Request) {
	// In production, serve from embedded FS.
	// Phase 11 serves the full dashboard HTML from this function.
	http.ServeFile(w, r, "/etc/falx/dashboard/index.html")
}
