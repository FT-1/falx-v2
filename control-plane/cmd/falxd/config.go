// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Centralized configuration types for the falxd control plane.
//              All subsystems reference this single config struct, ensuring
//              a single source of truth for runtime parameters.
// =============================================================================

package main

import (
	"os"

	"github.com/BurntSushi/toml"
)

// ─── Root Config ──────────────────────────────────────────────────────────────
type FalxConfig struct {
	General  GeneralConfig  `toml:"general"`
	XDP      XDPConfig      `toml:"xdp"`
	Maps     MapsConfig     `toml:"maps"`
	Failsafe FailsafeConfig `toml:"failsafe"`
	AFXDP    AFXDPConfig    `toml:"afxdp"`
	AI       AIConfig       `toml:"ai"`
	SOC      SOCConfig      `toml:"soc"`
	Metrics  MetricsConfig  `toml:"metrics"`
}

type GeneralConfig struct {
	LogLevel string `toml:"log_level"`
	Iface    string `toml:"iface"`
	PinPath  string `toml:"pin_path"`
}

type XDPConfig struct {
	Mode string `toml:"mode"` // "native" | "skb" | "offload"
}

type MapsConfig struct {
	BlocklistMaxEntries  uint32 `toml:"blocklist_max_entries"`
	RateLimitMaxEntries  uint32 `toml:"rate_limit_max_entries"`
	StatsMaxEntries      uint32 `toml:"stats_max_entries"`
	// Rate-limiting for map write operations (Phase 3)
	MapWriteRateLimitRPS uint32 `toml:"map_write_rate_limit_rps"`
}

type FailsafeConfig struct {
	PPSThreshold  uint64 `toml:"pps_threshold"`
	BPSThreshold  uint64 `toml:"bps_threshold"`
	CooldownSecs  uint64 `toml:"cooldown_secs"`
	// Auto-drop mode when circuit breaker is open (Phase 5)
	AutoDropMode  bool   `toml:"auto_drop_mode"`
}

type AFXDPConfig struct {
	// Zero-copy bridge config (Phase 4)
	UMEMSize      uint32 `toml:"umem_size"`       // Number of frames in UMEM
	FrameSize     uint32 `toml:"frame_size"`      // Frame size in bytes (2048 or 4096)
	BatchSize     uint32 `toml:"batch_size"`      // RX/TX batch processing size
	QueueID       uint32 `toml:"queue_id"`        // NIC queue to bind
	NumFillFrames uint32 `toml:"num_fill_frames"` // Pre-filled FILL ring frames
}

type AIConfig struct {
	// AI inference endpoint (Phase 9)
	GRPCAddr      string `toml:"grpc_addr"`
	TimeoutMs     uint32 `toml:"timeout_ms"`
	MaxRetries    uint32 `toml:"max_retries"`
	// Confidence threshold below which we block by default
	BlockThreshold float64 `toml:"block_threshold"`
}

type SOCConfig struct {
	GRPCAddr  string `toml:"grpc_addr"`
	WSAddr    string `toml:"ws_addr"`
}

type MetricsConfig struct {
	PrometheusAddr string `toml:"prometheus_addr"`
	Enabled        bool   `toml:"enabled"`
}

// ─── LoadConfig reads TOML from disk ─────────────────────────────────────────
func LoadConfig(path string) (*FalxConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg FalxConfig
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ─── DefaultConfig returns safe built-in defaults ─────────────────────────────
func DefaultConfig() *FalxConfig {
	return &FalxConfig{
		General: GeneralConfig{
			LogLevel: "info",
			Iface:    "eth0",
			PinPath:  "/sys/fs/bpf/falx",
		},
		XDP: XDPConfig{
			Mode: "native",
		},
		Maps: MapsConfig{
			BlocklistMaxEntries:  65536,
			RateLimitMaxEntries:  65536,
			StatsMaxEntries:      256,
			MapWriteRateLimitRPS: 10000,
		},
		Failsafe: FailsafeConfig{
			PPSThreshold: 1_000_000,
			BPSThreshold: 10_000_000_000,
			CooldownSecs: 30,
			AutoDropMode: true,
		},
		AFXDP: AFXDPConfig{
			UMEMSize:      4096,
			FrameSize:     2048,
			BatchSize:     64,
			QueueID:       0,
			NumFillFrames: 2048,
		},
		AI: AIConfig{
			GRPCAddr:       "127.0.0.1:50051",
			TimeoutMs:      100,
			MaxRetries:     3,
			BlockThreshold: 0.85,
		},
		SOC: SOCConfig{
			GRPCAddr: "0.0.0.0:50052",
			WSAddr:   "0.0.0.0:8080",
		},
		Metrics: MetricsConfig{
			PrometheusAddr: "0.0.0.0:9090",
			Enabled:        true,
		},
	}
}
