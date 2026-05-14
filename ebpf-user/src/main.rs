// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: eBPF user-space loader main entry point (ebpf-user/src/main.rs).
//              Phase 2: Full BPF program lifecycle management.
//                - Loads embedded XDP object into kernel
//                - Attaches to target interface in native/skb/offload mode
//                - Pins maps to /sys/fs/bpf/falx for cross-process sharing
//                - Initializes CONFIG and FAILSAFE_STATE maps
//                - Runs stats polling loop with graceful shutdown
// =============================================================================

mod loader;
mod types;

use anyhow::{Context, Result};
use clap::Parser;
use log::{info, warn, error, debug};
use std::path::PathBuf;
use std::time::Duration;
use tokio::time;

use loader::{FalxHandle, LoaderConfig, MapManager, XdpAttachMode};
use types::{FailsafeState, FalxMapConfig, action};

// ─── CLI Arguments ────────────────────────────────────────────────────────────
#[derive(Debug, Parser)]
#[command(
    name    = "falx-user",
    about   = "FALX V2 eBPF/XDP Loader | Lead Architect: FT-1",
    version = "0.2.0"
)]
pub struct Args {
    #[arg(short = 'i', long, default_value = "eth0")]
    pub iface: String,

    #[arg(short = 'c', long, default_value = "/etc/falx/falx.toml")]
    pub config: PathBuf,

    #[arg(short = 'm', long, value_enum, default_value = "native")]
    pub mode: CliXdpMode,

    #[arg(short = 'v', long, action = clap::ArgAction::SetTrue)]
    pub verbose: bool,

    #[arg(long, default_value = "/sys/fs/bpf/falx")]
    pub pin_path: PathBuf,

    /// Packets per second threshold to trigger circuit breaker
    #[arg(long, default_value = "1000000")]
    pub pps_threshold: u64,

    /// Bits per second threshold to trigger circuit breaker
    #[arg(long, default_value = "10000000000")]
    pub bps_threshold: u64,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum CliXdpMode {
    Native,
    Skb,
    Offload,
}

impl From<CliXdpMode> for XdpAttachMode {
    fn from(m: CliXdpMode) -> XdpAttachMode {
        match m {
            CliXdpMode::Native  => XdpAttachMode::Native,
            CliXdpMode::Skb     => XdpAttachMode::Skb,
            CliXdpMode::Offload => XdpAttachMode::Offload,
        }
    }
}

// ─── Entry Point ─────────────────────────────────────────────────────────────
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_logger(args.verbose);

    // Verify root / CAP_BPF
    check_privileges()?;

    info!("=== FALX V2 eBPF Loader | Lead Architect: FT-1 | v0.2.0 ===");
    info!("Target interface: {} | XDP mode: {:?}", args.iface, args.mode);

    // ── Build Loader Config ────────────────────────────────────────────────────
    let map_config = FalxMapConfig {
        default_action:     action::PASS,
        rate_limit_enabled: 1,
        failsafe_enabled:   1,
        afxdp_redirect:     0,
        _pad:               [0u8; 4],
        rate_capacity:      1_000,      // 1000 packets burst
        rate_refill_ns:     1_000_000,  // 1 token per millisecond
        honeypot_ip:        0,
        honeypot_port:      0,
        _pad2:              [0u8; 2],
    };

    let failsafe_init = FailsafeState {
        circuit_open:    0,
        _pad:            [0u8; 7],
        current_pps:     0,
        current_bps:     0,
        open_since_ns:   0,
        pps_threshold:   args.pps_threshold,
        bps_threshold:   args.bps_threshold,
        window_start_ns: 0,
    };

    let loader_cfg = LoaderConfig {
        iface:         args.iface.clone(),
        xdp_mode:      args.mode.clone().into(),
        pin_path:      args.pin_path.clone(),
        map_config,
        failsafe_init,
    };

    // ── Load and Attach XDP Program ───────────────────────────────────────────
    let handle = loader::load_and_attach(&loader_cfg).await
        .with_context(|| format!(
            "Failed to load XDP program on '{}'. \
             Check: kernel >= 5.15, interface exists, running as root.",
            args.iface
        ))?;

    let map_mgr = MapManager::new(args.pin_path.clone());

    // ── Run Stats Polling + Signal Handler ────────────────────────────────────
    run_event_loop(handle, map_mgr).await?;

    info!("FALX V2 eBPF loader exited cleanly.");
    Ok(())
}

// ─── Main Event Loop ──────────────────────────────────────────────────────────
async fn run_event_loop(_handle: FalxHandle, map_mgr: MapManager) -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint  = signal(SignalKind::interrupt())?;
    let mut sighupp = signal(SignalKind::hangup())?;     // SIGHUP = reload config

    // Stats polling interval
    let mut stats_ticker = time::interval(Duration::from_secs(5));

    info!("FALX V2 running. Monitoring for signals (SIGINT/SIGTERM=shutdown, SIGHUP=stats)");

    loop {
        tokio::select! {
            // ── Periodic Stats Poll ──────────────────────────────────────────
            _ = stats_ticker.tick() => {
                match map_mgr.read_stats() {
                    Ok(stats) => {
                        info!(
                            "Stats | rx={} ({} MB) | drop={} | rate_limit={} | \
                             pass={} | failsafe_drop={} | parse_err={}",
                            stats.rx_packets,
                            stats.rx_bytes / 1_000_000,
                            stats.dropped,
                            stats.rate_limited,
                            stats.passed,
                            stats.failsafe_drops,
                            stats.parse_errors,
                        );
                    }
                    Err(e) => {
                        warn!("Stats read failed: {}", e);
                    }
                }
            }

            // ── SIGHUP: Log current stats (no reload needed, config via maps) ─
            _ = sighupp.recv() => {
                info!("SIGHUP received — current stats:");
                if let Ok(stats) = map_mgr.read_stats() {
                    info!("{:?}", stats);
                }
            }

            // ── Graceful Shutdown ────────────────────────────────────────────
            _ = sigterm.recv() => {
                warn!("SIGTERM received — shutting down FALX V2");
                break;
            }
            _ = sigint.recv() => {
                warn!("SIGINT received — shutting down FALX V2");
                break;
            }
        }
    }

    // _handle drops here → XDP program detaches, maps unpinned by kernel GC
    info!("XDP program detached from interface.");
    Ok(())
}

// ─── Privilege Check ─────────────────────────────────────────────────────────
fn check_privileges() -> Result<()> {
    // Check for root or CAP_BPF + CAP_NET_ADMIN
    let uid = unsafe { libc::getuid() };
    if uid != 0 {
        warn!(
            "Not running as root (uid={}). \
             BPF operations require CAP_BPF + CAP_NET_ADMIN. \
             Consider: sudo setcap cap_bpf,cap_net_admin+ep falx-user",
            uid
        );
    }
    // Non-fatal: let the BPF load fail with a clear kernel error if unprivileged
    Ok(())
}

// ─── Logger ───────────────────────────────────────────────────────────────────
fn init_logger(verbose: bool) {
    let level = if verbose { "debug" } else { "info" };
    std::env::set_var(
        "RUST_LOG",
        format!("falx_user={},aya={}", level, if verbose { "debug" } else { "warn" })
    );
    env_logger::Builder::from_env(env_logger::Env::default())
        .format_timestamp_millis()
        .init();
}
