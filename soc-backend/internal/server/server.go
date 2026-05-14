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
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"

	authpkg   "github.com/ft-1/falx-v2/control-plane/pkg/auth"
	"github.com/ft-1/falx-v2/control-plane/pkg/bpfmaps"
	"github.com/ft-1/falx-v2/control-plane/pkg/events"
	"github.com/ft-1/falx-v2/control-plane/pkg/notifications"
	"github.com/ft-1/falx-v2/control-plane/pkg/policy"
	"github.com/ft-1/falx-v2/soc-backend/internal/api"
)

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
	notifMgr   *notifications.Manager
}

// ─── Constructor ──────────────────────────────────────────────────────────────
func New(cfg *Config, log *zap.Logger) (*Server, error) {
	s := &Server{cfg: cfg, log: log}
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

	// BPF Maps
	mgrCfg := bpfmaps.ManagerConfig{
		PinPath:       s.cfg.PinPath,
		RLConfig:      bpfmaps.DefaultRateLimitConfig(),
		AuditLogPath:  "/var/log/falx/audit.jsonl",
		SweepInterval: 60 * time.Second,
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
	dashH    := api.NewDashboardHandler(s.bpfMgr, s.policyEng, s.eventBus, s.log)
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

	// ── Authenticated: all roles ──────────────────────────────────────────
	authed := r.PathPrefix("/api/v1").Subrouter()
	authed.Use(auth.RequireAuth)

	authed.HandleFunc("/auth/logout",        authH.Logout).Methods(http.MethodPost)
	authed.HandleFunc("/auth/logout-all",    authH.LogoutAll).Methods(http.MethodPost)
	authed.HandleFunc("/auth/me",            authH.Me).Methods(http.MethodGet)
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
	authed.Handle("/audit",              auth.RequirePermission(authpkg.PermAuditRead)(http.HandlerFunc(authH.GetAuditLog))).Methods(http.MethodGet)
	authed.Handle("/system/config",      superPerm(http.HandlerFunc(systemH.GetConfig))).Methods(http.MethodGet)
	authed.Handle("/system/config",      superPerm(http.HandlerFunc(systemH.UpdateConfig))).Methods(http.MethodPut)
	authed.Handle("/system/metrics-summary", adminPerm(http.HandlerFunc(systemH.MetricsSummary))).Methods(http.MethodGet)

	// ── WebSocket — viewer+ ───────────────────────────────────────────────
	r.Handle("/ws", auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		claims := authpkg.ClaimsFromContext(req.Context())
		if claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.notifMgr.Hub().HandleUpgrade(w, req, claims.UserID, string(claims.Role))
	})))

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

// serveDashboard serves the embedded SOC dashboard HTML for all unmatched paths.
func serveDashboard(w http.ResponseWriter, r *http.Request) {
	// In production, serve from embedded FS.
	// Phase 11 serves the full dashboard HTML from this function.
	http.ServeFile(w, r, "/etc/falx/dashboard/index.html")
}
