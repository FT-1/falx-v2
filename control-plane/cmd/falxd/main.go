//go:build linux
// +build linux

// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: falxd main entry point (control-plane/cmd/falxd/main.go).
//              Phase 7 final: complete daemon entry point that:
//                - Parses CLI flags
//                - Loads TOML config with override support
//                - Initialises the structured logger
//                - Validates kernel and capability requirements
//                - Creates and runs FalxDaemon (daemon.go)
//                - Returns exit codes compatible with systemd
// =============================================================================

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Build-time metadata (injected via Makefile -ldflags)
var (
	Version   = "0.1.0-dev"
	BuildTime = "unknown"
)

// ─── Exit Codes ───────────────────────────────────────────────────────────────
const (
	ExitOK            = 0
	ExitConfigErr     = 1
	ExitPrivilegeErr  = 2
	ExitKernelErr     = 3
	ExitRuntimeErr    = 4
)

// ─── CLI Flags ────────────────────────────────────────────────────────────────
var (
	flagConfig   = flag.String("config",   "/etc/falx/falx.toml", "TOML config file path")
	flagIface    = flag.String("iface",    "",                     "Override: network interface")
	flagMode     = flag.String("mode",     "",                     "Override: xdp mode (native|skb|offload)")
	flagPinPath  = flag.String("pin-path", "",                     "Override: BPF pin path")
	flagMetrics  = flag.String("metrics",  "",                     "Override: Prometheus addr (host:port)")
	flagLogLevel = flag.String("log-level","",                     "Override: log level (debug|info|warn|error)")
	flagVerbose  = flag.Bool("verbose",    false,                  "Alias for --log-level=debug")
	flagVersion  = flag.Bool("version",    false,                  "Print version and exit")
	flagDryRun   = flag.Bool("dry-run",    false,                  "Validate config + capabilities, then exit")
	flagNoColor  = flag.Bool("no-color",   false,                  "Disable colored log output")
)

// ─── Entry Point ──────────────────────────────────────────────────────────────
func main() {
	flag.Parse()

	if *flagVersion {
		fmt.Printf("FALX V2 falxd\n  Version:   %s\n  Built:     %s\n  Architect: FT-1\n  Go:        %s\n",
			Version, BuildTime, runtime.Version())
		os.Exit(ExitOK)
	}

	// ── Logger ────────────────────────────────────────────────────────────
	logLevel := resolveLogLevel()
	log, err := buildLogger(logLevel, *flagNoColor)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logger init failed: %v\n", err)
		os.Exit(ExitConfigErr)
	}
	defer log.Sync() //nolint:errcheck

	log.Info("FALX V2 falxd",
		zap.String("version",   Version),
		zap.String("built",     BuildTime),
		zap.String("go",        runtime.Version()),
		zap.String("architect", "FT-1"),
	)

	// ── Config ────────────────────────────────────────────────────────────
	cfg, err := LoadConfig(*flagConfig)
	if err != nil {
		log.Warn("Config load failed — using built-in defaults", zap.Error(err))
		cfg = DefaultConfig()
	}
	applyOverrides(cfg)

	log.Info("Configuration active",
		zap.String("iface",    cfg.General.Iface),
		zap.String("xdp_mode", cfg.XDP.Mode),
		zap.String("pin_path", cfg.General.PinPath),
		zap.Uint64("pps_threshold", cfg.Failsafe.PPSThreshold),
	)

	// ── Pre-flight Checks ─────────────────────────────────────────────────
	if err := preflightChecks(log); err != nil {
		log.Error("Pre-flight check failed", zap.Error(err))
		os.Exit(ExitPrivilegeErr)
	}

	if *flagDryRun {
		log.Info("Dry-run: all checks passed. Exiting.")
		os.Exit(ExitOK)
	}

	// ── Daemon ────────────────────────────────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown on SIGTERM / SIGINT
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		log.Info("Signal received — shutting down", zap.String("signal", sig.String()))
		cancel()
	}()

	daemon := NewFalxDaemon(cfg, log)

	if err := daemon.Run(ctx); err != nil {
		log.Error("Daemon exited with error", zap.Error(err))
		os.Exit(ExitRuntimeErr)
	}

	log.Info("falxd exited cleanly.")
	os.Exit(ExitOK)
}

// ─── Config CLI Overrides ─────────────────────────────────────────────────────
func applyOverrides(cfg *FalxConfig) {
	if *flagIface    != "" { cfg.General.Iface               = *flagIface    }
	if *flagMode     != "" { cfg.XDP.Mode                    = *flagMode     }
	if *flagPinPath  != "" { cfg.General.PinPath             = *flagPinPath  }
	if *flagMetrics  != "" { cfg.Metrics.PrometheusAddr      = *flagMetrics  }
	if *flagLogLevel != "" { cfg.General.LogLevel            = *flagLogLevel }
}

// ─── Log Level Resolution ─────────────────────────────────────────────────────
func resolveLogLevel() string {
	if *flagVerbose {
		return "debug"
	}
	if *flagLogLevel != "" {
		return *flagLogLevel
	}
	return "info"
}

// ─── Logger Factory ───────────────────────────────────────────────────────────
func buildLogger(level string, noColor bool) (*zap.Logger, error) {
	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		zapLevel = zapcore.InfoLevel
	}

	encCfg := zap.NewProductionEncoderConfig()
	encCfg.EncodeTime  = zapcore.ISO8601TimeEncoder
	encCfg.EncodeLevel = zapcore.CapitalLevelEncoder

	enc := "json"
	if !noColor && isTerminal(os.Stdout) {
		enc = "console"
		encCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	zapCfg := zap.Config{
		Level:            zap.NewAtomicLevelAt(zapLevel),
		Development:      zapLevel == zapcore.DebugLevel,
		Encoding:         enc,
		EncoderConfig:    encCfg,
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}
	return zapCfg.Build()
}

func isTerminal(f *os.File) bool {
	var termios syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		f.Fd(), syscall.TCGETS, uintptr(unsafe.Pointer(&termios)))
	return errno == 0
}

// ─── Pre-flight Checks ────────────────────────────────────────────────────────
func preflightChecks(log *zap.Logger) error {
	// ── Kernel version ────────────────────────────────────────────────────
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err == nil {
		release := int8SliceToString(uname.Release[:])
		log.Info("Kernel", zap.String("release", release))
		if !kernelAtLeast(release, 5, 15) {
			return fmt.Errorf("kernel %s < 5.15 — XDP native mode and eBPF features required", release)
		}
	}

	// ── UID / Capabilities ────────────────────────────────────────────────
	if os.Getuid() != 0 {
		log.Warn("Not running as root — BPF operations require CAP_BPF + CAP_NET_ADMIN",
			zap.Int("uid", os.Getuid()))
	}

	// ── BPF filesystem ────────────────────────────────────────────────────
	if _, err := os.Stat("/sys/fs/bpf"); err != nil {
		return fmt.Errorf("BPF filesystem not mounted at /sys/fs/bpf: %w", err)
	}

	// ── Audit log directory ───────────────────────────────────────────────
	if err := os.MkdirAll("/var/log/falx", 0o750); err != nil {
		log.Warn("Cannot create audit log directory", zap.Error(err))
	}

	log.Info("Pre-flight checks passed")
	return nil
}

// ─── Kernel Version Check ─────────────────────────────────────────────────────
func kernelAtLeast(release string, major, minor int) bool {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return true // Unknown: allow
	}
	maj, _ := strconv.Atoi(parts[0])
	min, _ := strconv.Atoi(strings.Split(parts[1], "-")[0])
	return maj > major || (maj == major && min >= minor)
}

func int8SliceToString(s []int8) string {
	b := make([]byte, 0, len(s))
	for _, v := range s {
		if v == 0 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}
