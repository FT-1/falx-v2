// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: BPF program loader (ebpf-user/src/loader.rs).
//              Responsible for:
//                1. Loading the compiled BPF object into the kernel
//                2. Attaching the XDP program to the target interface
//                3. Pinning all BPF maps to the BPF filesystem
//                4. Pushing initial config values into the CONFIG map
//                5. Returning a handle for the running program
//
//              The BPF object is embedded at compile time via include_bytes!()
//              so no external .o file is needed at runtime — the binary is
//              fully self-contained.
// =============================================================================

use anyhow::{anyhow, Context, Result};
use aya::{
    // aya 0.13 exposes ONE user-space `HashMap` type that works for both
    // regular BPF_MAP_TYPE_HASH and BPF_MAP_TYPE_LRU_HASH kernel maps —
    // the underlying kernel map type was already fixed at program load time
    // (via the #[map] attribute in ebpf-kern), so no LruHashMap variant
    // exists on the user side.
    //
    // The `Map` enum is required when opening a pinned map: aya 0.13 only
    // implements `TryFrom<Map>` (not `TryFrom<MapData>`) for the typed map
    // wrappers, so each pinned `MapData` must be wrapped in its correct
    // enum variant (e.g. `Map::LruHashMap(...)`, `Map::Array(...)`) before
    // being converted into the strongly-typed view.
    maps::{Array, HashMap, Map, PerCpuArray},
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use log::{info, warn, debug};
use std::path::{Path, PathBuf};

use crate::types::{FailsafeState, FalxMapConfig};

// ─── Embedded BPF Object ──────────────────────────────────────────────────────
// The BPF .o file is compiled by build.rs and embedded here.
// At runtime, no external file access is needed.
// NOTE: Path is relative to the build artifact — adjusted by aya-build.
//
// MUST use aya::include_bytes_aligned! (not std's include_bytes!): the `object`
// crate that aya uses to parse the embedded ELF requires the byte slice to be
// 8-byte aligned and rejects byte-aligned slices with
// "Invalid ELF header size or alignment" (surfaced through aya as
// ParseError::ElfError → "error parsing ELF data"). include_bytes!  produces
// a &[u8; N] with alignment 1 — anchoring the bytes inside an
// #[repr(align(32))] wrapper (what include_bytes_aligned! does) gives the
// parser the alignment it needs.
static BPF_OBJECT: &[u8] = aya::include_bytes_aligned!(
    concat!(env!("OUT_DIR"), "/falx-kern.bpf.o")
);

// ─── Loader Configuration ─────────────────────────────────────────────────────
pub struct LoaderConfig {
    pub iface:         String,
    pub xdp_mode:      XdpAttachMode,
    pub pin_path:      PathBuf,
    pub map_config:    FalxMapConfig,
    pub failsafe_init: FailsafeState,
}

#[derive(Debug, Clone, Copy)]
pub enum XdpAttachMode {
    Native,
    Skb,
    Offload,
}

impl From<XdpAttachMode> for XdpFlags {
    fn from(m: XdpAttachMode) -> XdpFlags {
        match m {
            XdpAttachMode::Native  => XdpFlags::DRV_MODE,
            XdpAttachMode::Skb     => XdpFlags::SKB_MODE,
            XdpAttachMode::Offload => XdpFlags::HW_MODE,
        }
    }
}

// ─── Running Program Handle ───────────────────────────────────────────────────
pub struct FalxHandle {
    /// Owned Ebpf instance — dropping this detaches the XDP program
    pub ebpf:    Ebpf,
    pub iface:   String,
    pub pin_path: PathBuf,
}

impl Drop for FalxHandle {
    fn drop(&mut self) {
        info!("Detaching XDP program from interface '{}'", self.iface);
        // Aya automatically detaches when Ebpf is dropped and programs
        // are not pinned to the BPF FS independently.
    }
}

// ─── Main Loader Function ─────────────────────────────────────────────────────
pub async fn load_and_attach(cfg: &LoaderConfig) -> Result<FalxHandle> {
    info!(
        "Loading FALX V2 XDP program | iface={} mode={:?}",
        cfg.iface, cfg.xdp_mode
    );

    // ── Load BPF Object from embedded bytes ───────────────────────────────────
    // aya's ParseError::ElfError variant has no #[source] annotation, so
    // anyhow's chain walker stops at "error parsing ELF data" and hides the
    // real underlying cause (CreateError + EPERM, RelocationError, etc.).
    // Logging Debug here exposes the actual variant + os_error to the journal
    // before we propagate; otherwise operators are stuck guessing.
    let mut ebpf = Ebpf::load(BPF_OBJECT)
        .map_err(|e| {
            log::error!("aya::Ebpf::load failed — full debug chain:\n{:#?}", e);
            e
        })
        .context("Failed to load BPF object. Ensure kernel >= 5.15 and CAP_BPF")?;

    // ── Initialize BPF Logger ──────────────────────────────────────────────────
    // aya-log bridges BPF kernel logs to user-space logger
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("BPF logger init failed (non-fatal): {}", e);
    }

    // ── Get and Attach XDP Program ────────────────────────────────────────────
    let program: &mut Xdp = ebpf
        .program_mut("falx_xdp")
        .ok_or_else(|| anyhow!("BPF program 'falx_xdp' not found in object"))?
        .try_into()
        .context("Failed to cast program to Xdp type")?;

    program.load()
        .context("BPF verifier rejected the program. Check kernel version and program complexity")?;

    let flags: XdpFlags = cfg.xdp_mode.into();
    program.attach(&cfg.iface, flags)
        .with_context(|| format!(
            "Failed to attach XDP to '{}'. Try --mode skb if native is unsupported.",
            cfg.iface
        ))?;

    info!("XDP program attached to '{}' (mode={:?})", cfg.iface, cfg.xdp_mode);

    // ── Pin Maps to BPF Filesystem ────────────────────────────────────────────
    // Pinning ensures maps survive falxd restarts and are accessible
    // by the control plane (Go) via file descriptor.
    pin_maps(&mut ebpf, &cfg.pin_path)
        .context("Failed to pin BPF maps to filesystem")?;

    // ── Initialize CONFIG Map ─────────────────────────────────────────────────
    init_config_map(&mut ebpf, &cfg.map_config)
        .context("Failed to initialize CONFIG map")?;

    // ── Initialize FAILSAFE_STATE Map ─────────────────────────────────────────
    init_failsafe_map(&mut ebpf, &cfg.failsafe_init)
        .context("Failed to initialize FAILSAFE_STATE map")?;

    info!("All BPF maps initialized and pinned at '{}'", cfg.pin_path.display());

    Ok(FalxHandle {
        ebpf,
        iface:    cfg.iface.clone(),
        pin_path: cfg.pin_path.clone(),
    })
}

// ─── Map Pinning ──────────────────────────────────────────────────────────────
fn pin_maps(ebpf: &mut Ebpf, pin_base: &Path) -> Result<()> {
    std::fs::create_dir_all(pin_base)
        .with_context(|| format!("Cannot create pin path '{}'", pin_base.display()))?;

    let maps_to_pin = [
        "BLOCKLIST_V4",
        "BLOCKLIST_V6",
        "RATE_LIMIT",
        "XDP_STATS",
        // MAPPED_XDP_STATS is the hot-path per-CPU accumulator written by
        // bump_mapped() for rx_packets / rx_bytes / passed / dropped.
        // It MUST be pinned so the Go control plane can read live counters.
        "MAPPED_XDP_STATS",
        "FAILSAFE_STATE",
        "CONFIG",
        "XSK_MAP",
        "HONEYPOT_TARGETS",
        "HONEYPOT_ACTIVE",
    ];

    for map_name in &maps_to_pin {
        let pin_file = pin_base.join(map_name.to_lowercase());

        // Remove stale pin if it exists
        if pin_file.exists() {
            debug!("Removing stale pin: {}", pin_file.display());
            std::fs::remove_file(&pin_file)?;
        }

        ebpf.map_mut(map_name)
            .ok_or_else(|| anyhow!("Map '{}' not found in BPF object", map_name))?
            .pin(&pin_file)
            .with_context(|| format!("Failed to pin map '{}' to '{}'", map_name, pin_file.display()))?;

        debug!("Pinned map '{}' → '{}'", map_name, pin_file.display());
    }

    info!("All {} BPF maps pinned successfully", maps_to_pin.len());
    Ok(())
}

// ─── Config Map Initialization ────────────────────────────────────────────────
fn init_config_map(ebpf: &mut Ebpf, config: &FalxMapConfig) -> Result<()> {
    let mut map: Array<_, FalxMapConfig> = Array::try_from(
        ebpf.map_mut("CONFIG")
            .ok_or_else(|| anyhow!("CONFIG map not found"))?
    )?;

    map.set(0, *config, 0)
        .context("Failed to write initial config to CONFIG map")?;

    info!("CONFIG map initialized (rate_limit={}, failsafe={})",
        config.rate_limit_enabled, config.failsafe_enabled);
    Ok(())
}

// ─── Failsafe State Initialization ───────────────────────────────────────────
fn init_failsafe_map(ebpf: &mut Ebpf, state: &FailsafeState) -> Result<()> {
    let mut map: Array<_, FailsafeState> = Array::try_from(
        ebpf.map_mut("FAILSAFE_STATE")
            .ok_or_else(|| anyhow!("FAILSAFE_STATE map not found"))?
    )?;

    map.set(0, *state, 0)
        .context("Failed to write initial state to FAILSAFE_STATE map")?;

    info!("FAILSAFE_STATE initialized (pps_threshold={}, bps_threshold={})",
        state.pps_threshold, state.bps_threshold);
    Ok(())
}

// ─── Map Update API (used by control plane at runtime) ────────────────────────
pub struct MapManager {
    pub pin_path: PathBuf,
}

impl MapManager {
    pub fn new(pin_path: PathBuf) -> Self {
        MapManager { pin_path }
    }

    /// Add or update an IPv4 block entry.
    /// Kernel-side map type: LruHashMap → must wrap in `Map::LruHashMap`.
    pub fn block_ipv4(
        &self,
        src_ip:   u32,
        entry:    crate::types::BlockEntry,
    ) -> Result<()> {
        use aya::maps::MapData;

        let pin = self.pin_path.join("blocklist_v4");
        let map_data = MapData::from_pin(&pin)
            .context("Failed to open BLOCKLIST_V4 from pin")?;
        let map_wrapped = Map::LruHashMap(map_data);
        let mut map: HashMap<_, u32, crate::types::BlockEntry> =
            HashMap::try_from(map_wrapped)?;

        map.insert(src_ip, entry, 0)
            .context("Failed to insert blocklist entry")?;

        debug!("Blocked IPv4: {:?}", src_ip);
        Ok(())
    }

    /// Remove an IPv4 block entry.
    /// Kernel-side map type: LruHashMap → must wrap in `Map::LruHashMap`.
    pub fn unblock_ipv4(&self, src_ip: u32) -> Result<()> {
        use aya::maps::MapData;

        let pin = self.pin_path.join("blocklist_v4");
        let map_data = MapData::from_pin(&pin)
            .context("Failed to open BLOCKLIST_V4 from pin")?;
        let map_wrapped = Map::LruHashMap(map_data);
        let mut map: HashMap<_, u32, crate::types::BlockEntry> =
            HashMap::try_from(map_wrapped)?;

        map.remove(&src_ip)
            .context("Failed to remove blocklist entry")?;

        debug!("Unblocked IPv4: {:?}", src_ip);
        Ok(())
    }

    /// Read aggregated stats from XDP_STATS PerCpuArray.
    /// Kernel-side map type: PerCpuArray → must wrap in `Map::PerCpuArray`.
    pub fn read_stats(&self) -> Result<crate::types::XdpStats> {
        use aya::maps::MapData;
        use crate::types::XdpStats;

        let pin = self.pin_path.join("xdp_stats");
        let map_data = MapData::from_pin(&pin)
            .context("Failed to open XDP_STATS from pin")?;
        let map_wrapped = Map::PerCpuArray(map_data);
        let map: PerCpuArray<_, XdpStats> = PerCpuArray::try_from(map_wrapped)?;

        // PerCpuArray returns a PerCpuValues vec — aggregate across CPUs
        let per_cpu = map.get(&0, 0)
            .context("Failed to read XDP_STATS")?;

        let aggregated = per_cpu.iter().fold(XdpStats::default(), |acc, s| acc + *s);
        Ok(aggregated)
    }

    /// Update runtime config without reloading the BPF program.
    /// Kernel-side map type: Array → must wrap in `Map::Array`.
    pub fn update_config(&self, config: FalxMapConfig) -> Result<()> {
        use aya::maps::MapData;

        let pin = self.pin_path.join("config");
        let map_data = MapData::from_pin(&pin)
            .context("Failed to open CONFIG from pin")?;
        let map_wrapped = Map::Array(map_data);
        let mut map: Array<_, FalxMapConfig> = Array::try_from(map_wrapped)?;

        map.set(0, config, 0)
            .context("Failed to update CONFIG map")?;

        info!("CONFIG map updated dynamically (no BPF reload required)");
        Ok(())
    }

    /// Close the circuit breaker (re-enable AI path).
    /// Kernel-side map type: Array → must wrap in `Map::Array`.
    pub fn close_circuit(&self) -> Result<()> {
        use aya::maps::MapData;

        let pin = self.pin_path.join("failsafe_state");
        let map_data = MapData::from_pin(&pin)
            .context("Failed to open FAILSAFE_STATE from pin")?;
        let map_wrapped = Map::Array(map_data);
        let mut map: Array<_, FailsafeState> = Array::try_from(map_wrapped)?;

        let mut state = map.get(&0, 0)
            .context("Failed to read FAILSAFE_STATE")?;
        state.circuit_open = 0;

        map.set(0, state, 0)
            .context("Failed to close circuit in FAILSAFE_STATE")?;

        info!("Circuit breaker CLOSED — AI inference path re-enabled");
        Ok(())
    }
}
