// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: SOC Backend entry point (soc-backend/cmd/main.go).
//              Launches the unified HTTP server exposing:
//                - REST API  (auth, security, admin, policy, dashboard)
//                - WebSocket (real-time event streaming to SOC dashboard)
//                - gRPC      (AI engine and control-plane communication)
//              All routes protected by JWT + RBAC middleware from Phase 9.
// =============================================================================

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/ft-1/falx-v2/soc-backend/internal/server"
)

var (
	Version   = "0.1.0"
	BuildTime = "unknown"
)

func main() {
	httpAddr   := flag.String("http",     "0.0.0.0:8080",    "HTTP/WS listen address")
	grpcAddr   := flag.String("grpc",     "0.0.0.0:50052",   "gRPC listen address")
	cpAddr     := flag.String("cp",       "127.0.0.1:50051", "Control plane gRPC address")
	dbPath     := flag.String("db",       "/var/lib/falx/soc.db", "SOC database path")
	authDBPath := flag.String("auth-db",  "/var/lib/falx/auth.db", "Auth database path")
	policyDB   := flag.String("policy-db","/var/lib/falx/policy.db", "Policy database path")
	pinPath    := flag.String("pin-path", "/sys/fs/bpf/falx", "BPF maps pin path")
	jwtPriv    := flag.String("jwt-priv", "/etc/falx/keys/jwt_private.pem", "JWT private key")
	jwtPub     := flag.String("jwt-pub",  "/etc/falx/keys/jwt_public.pem",  "JWT public key")
	verbose    := flag.Bool("verbose",    false, "Debug logging")
	versionFlag:= flag.Bool("version",   false, "Print version")
	devMode    := flag.Bool("dev",        os.Getenv("FALX_DEV") == "1",
		"Dev mode: fixed admin TOTP, auto-unlock accounts, print token on startup")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("FALX V2 SOC Backend v%s (built %s) | Architect: FT-1\n", Version, BuildTime)
		os.Exit(0)
	}

	log := buildLogger(*verbose)
	defer log.Sync()

	log.Info("FALX V2 SOC Backend starting",
		zap.String("version",    Version),
		zap.String("http",       *httpAddr),
		zap.String("grpc",       *grpcAddr),
		zap.String("architect",  "FT-1"),
	)

	cfg := &server.Config{
		HTTPAddr:    *httpAddr,
		GRPCAddr:    *grpcAddr,
		CPAddr:      *cpAddr,
		DBPath:      *dbPath,
		AuthDBPath:  *authDBPath,
		PolicyDBPath: *policyDB,
		PinPath:     *pinPath,
		JWTPrivPath: *jwtPriv,
		JWTPubPath:  *jwtPub,
		Dev:         *devMode,
		AllowedOrigins: []string{
			"http://localhost:3000",
			"http://localhost:8080",
			"https://soc.falx.local",
		},
	}

	srv, err := server.New(cfg, log)
	if err != nil {
		log.Fatal("Server init failed", zap.Error(err))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		if err := srv.Run(ctx); err != nil {
			log.Error("Server error", zap.Error(err))
			cancel()
		}
	}()

	for {
		sig := <-sigCh
		switch sig {
		case syscall.SIGHUP:
			log.Info("SIGHUP: reloading configuration")
			srv.Reload()
		default:
			log.Warn("Shutdown signal received", zap.String("signal", sig.String()))
			cancel()
			shutCtx, shutCancel := context.WithTimeout(context.Background(), 15*time.Second)
			srv.Shutdown(shutCtx)
			shutCancel()
			log.Info("SOC Backend stopped cleanly")
			return
		}
	}
}

func buildLogger(verbose bool) *zap.Logger {
	level := zapcore.InfoLevel
	if verbose {
		level = zapcore.DebugLevel
	}
	cfg := zap.Config{
		Level:            zap.NewAtomicLevelAt(level),
		Encoding:         "json",
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "ts",
			LevelKey:       "level",
			MessageKey:     "msg",
			CallerKey:      "caller",
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
			LineEnding:     zapcore.DefaultLineEnding,
		},
	}
	l, _ := cfg.Build()
	return l
}
