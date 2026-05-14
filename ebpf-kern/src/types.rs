// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Shared data types for eBPF/XDP kernel program (ebpf-kern/src/types.rs).
//              These structs are the ARCHITECTURAL CONTRACT between the kernel
//              program (Rust/BPF), the user-space loader (Rust), and the
//              control plane (Go). Any change here MUST be mirrored in:
//                - ebpf-user/src/types.rs   (same layout, std-Rust)
//                - control-plane/internal/bpfmaps/types.go (Go equivalent)
//              All structs use repr(C) + packed to guarantee ABI stability.
// =============================================================================

use aya_ebpf::cty::c_uint;

// ─── IPv4 Block Entry ──────────────────────────────────────────────────────────
// Stored in BLOCKLIST_V4 map. Key = src_ip (u32, network byte order).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct BlockEntry {
    /// Unix timestamp (seconds) when this entry expires. 0 = permanent.
    pub expire_at:   u64,
    /// Action to take: see XdpAction constants below
    pub action:      u8,
    /// Rule ID that generated this block (0 = manual, 1-255 = AI rule)
    pub rule_id:     u8,
    /// Threat score from AI (0-100). 0 for manual blocks.
    pub threat_score: u8,
    /// Padding to align to 8 bytes
    pub _pad:        u8,
    /// Reason code for telemetry
    pub reason:      u32,
}

// ─── Rate Limit Bucket ────────────────────────────────────────────────────────
// Stored in RATE_LIMIT map. Key = src_ip (u32).
// Uses token bucket algorithm. All values in kernel-space atomic semantics.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RateBucket {
    /// Current token count (packets allowed until refill)
    pub tokens:       u64,
    /// Last refill timestamp (nanoseconds, from bpf_ktime_get_ns())
    pub last_refill:  u64,
    /// Max tokens (burst capacity). Configured via FalxMapConfig.
    pub capacity:     u64,
    /// Refill rate: tokens added per nanosecond
    pub refill_rate:  u64,
    /// Total drops from this source (for telemetry)
    pub drop_count:   u64,
}

// ─── Per-CPU Statistics ───────────────────────────────────────────────────────
// Stored in XDP_STATS PerCpuArray. Index 0 = global counters.
// PerCpu variant ensures lock-free writes from concurrent cores.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct XdpStats {
    pub rx_packets:     u64,  // Total packets received
    pub rx_bytes:       u64,  // Total bytes received
    pub dropped:        u64,  // Packets dropped by blocklist
    pub rate_limited:   u64,  // Packets dropped by rate limiter
    pub passed:         u64,  // Packets passed to network stack
    pub redirected:     u64,  // Packets redirected to AF_XDP/honeypot
    pub failsafe_drops: u64,  // Drops due to circuit breaker open
    pub parse_errors:   u64,  // Malformed packet errors
    pub map_errors:     u64,  // BPF map lookup failures
    /// Timestamps for rate-of-change calculation by control plane
    pub last_reset_ns:  u64,
}

// ─── Failsafe State (Circuit Breaker) ────────────────────────────────────────
// Stored in FAILSAFE_STATE Array. Index 0 = current state.
// Written by BOTH the XDP program (pps/bps counters) and
// the control plane (circuit open/close decisions).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FailsafeState {
    /// 1 = circuit OPEN (AI bypassed, pure-drop mode active)
    pub circuit_open:   u8,
    pub _pad:           [u8; 7],
    /// Rolling 1-second packet count (updated by XDP, sampled by CP)
    pub current_pps:    u64,
    /// Rolling 1-second byte count
    pub current_bps:    u64,
    /// Nanosecond timestamp when circuit was last opened
    pub open_since_ns:  u64,
    /// PPS threshold above which XDP opens the circuit
    pub pps_threshold:  u64,
    /// BPS threshold above which XDP opens the circuit
    pub bps_threshold:  u64,
    /// Window start for rolling counter (1-second window in ns)
    pub window_start_ns: u64,
}

// ─── Runtime Config (Control Plane → XDP) ────────────────────────────────────
// Stored in CONFIG Array. Index 0 = active config.
// Control plane writes this to push policy changes into the kernel
// without reloading the BPF program.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FalxMapConfig {
    /// Default action for packets NOT in any map: 0=PASS, 2=DROP
    pub default_action:       u8,
    /// Enable rate limiting subsystem (0 = disabled)
    pub rate_limit_enabled:   u8,
    /// Enable failsafe circuit breaker (0 = disabled)
    pub failsafe_enabled:     u8,
    /// Enable AF_XDP redirect for user-space inspection (Phase 4)
    pub afxdp_redirect:       u8,
    pub _pad:                 [u8; 4],
    /// Rate limit: max tokens per source IP
    pub rate_capacity:        u64,
    /// Rate limit: refill rate (tokens per nanosecond)
    pub rate_refill_ns:       u64,
    /// Honeypot redirect destination IP (Phase 6)
    pub honeypot_ip:          u32,
    pub honeypot_port:        u16,
    pub _pad2:                [u8; 2],
}

// ─── Action Constants (mirrors proto Action enum) ─────────────────────────────
pub mod action {
    pub const PASS:       u8 = 1;
    pub const DROP:       u8 = 2;
    pub const REDIRECT:   u8 = 3;  // To honeypot (Phase 6)
    pub const RATE_LIMIT: u8 = 4;
}

// ─── Reason Codes ─────────────────────────────────────────────────────────────
pub mod reason {
    pub const BLOCKLIST:    u32 = 0x0001;
    pub const RATE_LIMIT:   u32 = 0x0002;
    pub const FAILSAFE:     u32 = 0x0003;
    pub const PARSE_ERR:    u32 = 0x0004;
    pub const AI_VERDICT:   u32 = 0x0005;
}

// ─── Protocol Constants ────────────────────────────────────────────────────────
pub mod proto {
    pub const ICMP:  u8  = 1;
    pub const TCP:   u8  = 6;
    pub const UDP:   u8  = 17;
    pub const ICMPV6:u8  = 58;
}

pub mod ethertype {
    pub const IPV4: u16 = 0x0800;
    pub const IPV6: u16 = 0x86DD;
    pub const ARP:  u16 = 0x0806;
}

// ─── Map Index Constants ──────────────────────────────────────────────────────
pub const STATS_IDX:    u32 = 0;
pub const FAILSAFE_IDX: u32 = 0;
pub const CONFIG_IDX:   u32 = 0;
