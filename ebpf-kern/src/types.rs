// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Shared data types for eBPF/XDP kernel program (ebpf-kern/src/types.rs).
//              These structs are the ARCHITECTURAL CONTRACT between the kernel
//              program (Rust/BPF), the user-space loader (Rust), and the
//              control plane (Go). Any change here MUST be mirrored in:
//                - ebpf-user/src/types.rs   (same layout, std-Rust)
//                - control-plane/internal/bpfmaps/types.go (Go equivalent)
//              All structs use repr(C) to guarantee ABI stability.
//
//              Phase-11 Cooling Tracker — Option B (Race-Tolerant Best-Effort):
//                CoolingEntry uses no bpf_spin_lock. repeat_count RMW is
//                best-effort under multi-CPU concurrent floods; under-counting
//                is tolerated in exchange for BTF-free map compatibility.
//                Layout (16 bytes, repr(C)):
//                  offset 0: repeat_count   (u32)
//                  offset 4: _pad           (u32)
//                  offset 8: last_ban_at_ns (u64)
// =============================================================================

// ─── IPv4 Block Entry ──────────────────────────────────────────────────────────
// Stored in BLOCKLIST_V4 map. Key = src_ip (u32, network byte order).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct BlockEntry {
    /// Unix timestamp (seconds) when this entry expires. 0 = permanent.
    pub expire_at:    u64,
    /// Action to take: see action constants below
    pub action:       u8,
    /// Rule ID that generated this block (0 = manual, 1–254 = AI rule, 0xFF = cooling-tracker)
    pub rule_id:      u8,
    /// Threat score from AI (0–100). repeat_count for cooling bans.
    pub threat_score: u8,
    pub _pad:         u8,
    /// Reason code for telemetry
    pub reason:       u32,
}

// ─── Rate Limit Bucket ────────────────────────────────────────────────────────
// Stored in RATE_LIMIT map. Key = src_ip (u32).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RateBucket {
    pub tokens:      u64,
    pub last_refill: u64,
    pub capacity:    u64,
    pub refill_rate: u64,
    pub drop_count:  u64,
}

// ─── Cooling Tracker Entry (Exponential Backoff Banning) ──────────────────────
// Stored in COOLING_TRACKER LRU map. Key = src_ip (u32, network byte order).
//
// Implements T_ban = T_base × 2^r  where T_base = COOLING_BASE_S (10 s).
// Option B: no bpf_spin_lock — BTF-free, race-tolerant best-effort escalation.
// Under high multi-CPU concurrency repeat_count may under-count; the banning
// outcome (BLOCKLIST_V4 insert) remains correct on all code paths.
//
//   r=0  →     10 s      r=4  →    160 s     r=8  →  2 560 s (~43 min)
//   r=1  →     20 s      r=5  →    320 s     r=12 → 40 960 s (~11 h)
//   r=2  →     40 s      r=6  →    640 s     r=16 →655 360 s (~7.5 days)
//   r=3  →     80 s      r=7  →  1 280 s
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CoolingEntry {
    /// Number of prior rate-limit violations (exponent r in T_ban = T_base × 2^r).
    /// Capped at MAX_COOLING_SHIFT = 16.
    pub repeat_count:   u32,
    pub _pad:           u32,
    /// bpf_ktime_get_ns() timestamp of the most recent auto-ban for this source.
    pub last_ban_at_ns: u64,
}

// Manual Default impl: zeroing the struct is the correct kernel-side init.
impl Default for CoolingEntry {
    fn default() -> Self {
        // SAFETY: CoolingEntry is repr(C); all fields (u32, u32, u64) are valid
        // at zero.
        unsafe { core::mem::zeroed() }
    }
}

/// Base ban duration in seconds. T_ban = COOLING_BASE_S << repeat_count.
pub const COOLING_BASE_S:    u64 = 10;
/// Maximum left-shift for the exponential backoff. Caps T_ban at 10 × 2^16 ≈ 7.5 days.
pub const MAX_COOLING_SHIFT: u32 = 16;

// ─── SYN Flood Counter Entry ──────────────────────────────────────────────────
// Stored in SYN_COUNTER LRU map. Key = src_ip (u32, network byte order).
// Tracks consecutive SYN packets without completing a 3-way handshake.
// When syn_count ≥ SYN_FLOOD_THRESHOLD AND ack_count == 0, check_syn_counter()
// bypasses the rate limiter and issues a max-penalty cooling ban (r = 8,
// T_ban ≥ 2560 s) directly, before tokens are consumed.
// ACK packets (handshake completions) reset syn_count and increment ack_count.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SynCountEntry {
    /// Consecutive SYN-only packets seen without a completing ACK.
    pub syn_count: u32,
    /// Total ACK packets seen from this source (handshake completions).
    pub ack_count: u32,
}

/// Drop threshold: ≥ 50 consecutive SYNs with zero ACKs triggers a penalty ban.
pub const SYN_FLOOD_THRESHOLD:  u32 = 50;
/// Minimum cooling repeat_count imposed on SYN flood sources: r=8 → T_ban = 2 560 s.
pub const SYN_FLOOD_PENALTY_R:  u32 = 8;

// ─── Per-CPU Statistics (extended) ───────────────────────────────────────────
// Stored in XDP_STATS PerCpuArray. Index 0 = global counters.
// Updated only on cold paths (rate_limited, failsafe_drops, parse_errors, etc.)
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct XdpStats {
    pub rx_packets:     u64,
    pub rx_bytes:       u64,
    pub dropped:        u64,
    pub rate_limited:   u64,
    pub passed:         u64,
    pub redirected:     u64,
    pub failsafe_drops: u64,
    pub parse_errors:   u64,
    pub map_errors:     u64,
    pub cooling_bans:   u64,  // auto-bans from the cooling tracker
    pub syn_flood_bans: u64,  // auto-bans from the SYN counter (r ≥ 8)
    pub last_reset_ns:  u64,
}

// ─── Compact Per-CPU Accumulator (MAPPED_XDP_STATS) ──────────────────────────
// 6 × u64 = 48 bytes — exactly one 64-byte cache line.
// MUST remain at exactly 48 bytes. DO NOT add fields.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct MappedXdpStats {
    pub rx_packets:    u64,
    pub rx_bytes:      u64,
    pub dropped:       u64,
    pub dropped_bytes: u64,
    pub passed:        u64,
    pub passed_bytes:  u64,
}

// ─── Failsafe State (Circuit Breaker) ────────────────────────────────────────
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FailsafeState {
    pub circuit_open:    u8,
    pub _pad:            [u8; 7],
    pub current_pps:     u64,
    pub current_bps:     u64,
    pub open_since_ns:   u64,
    pub pps_threshold:   u64,
    pub bps_threshold:   u64,
    pub window_start_ns: u64,
}

// ─── Runtime Config (Control Plane → XDP) ────────────────────────────────────
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FalxMapConfig {
    pub default_action:     u8,
    pub rate_limit_enabled: u8,
    pub failsafe_enabled:   u8,
    pub afxdp_redirect:     u8,
    pub _pad:               [u8; 4],
    pub rate_capacity:      u64,
    pub rate_refill_ns:     u64,
    pub honeypot_ip:        u32,
    pub honeypot_port:      u16,
    pub _pad2:              [u8; 2],
}

// ─── Action Constants ─────────────────────────────────────────────────────────
pub mod action {
    pub const PASS:       u8 = 1;
    pub const DROP:       u8 = 2;
    pub const REDIRECT:   u8 = 3;
    pub const RATE_LIMIT: u8 = 4;
}

// ─── Reason Codes ─────────────────────────────────────────────────────────────
pub mod reason {
    pub const BLOCKLIST:   u32 = 0x0001;
    pub const RATE_LIMIT:  u32 = 0x0002;
    pub const FAILSAFE:    u32 = 0x0003;
    pub const PARSE_ERR:   u32 = 0x0004;
    pub const AI_VERDICT:  u32 = 0x0005;
    pub const COOLING_BAN: u32 = 0x0006;
}

// ─── Protocol Constants ────────────────────────────────────────────────────────
pub mod proto {
    pub const ICMP:   u8 = 1;
    pub const TCP:    u8 = 6;
    pub const UDP:    u8 = 17;
    pub const ICMPV6: u8 = 58;
}

pub mod ethertype {
    pub const IPV4: u16 = 0x0800;
    pub const IPV6: u16 = 0x86DD;
    pub const ARP:  u16 = 0x0806;
}

// ─── Map Index Constants ──────────────────────────────────────────────────────
pub const STATS_IDX:        u32 = 0;
pub const MAPPED_STATS_IDX: u32 = 0;
pub const FAILSAFE_IDX:     u32 = 0;
pub const CONFIG_IDX:       u32 = 0;
