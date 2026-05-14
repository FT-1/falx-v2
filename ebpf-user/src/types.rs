// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: User-space mirror of BPF kernel types (ebpf-user/src/types.rs).
//              These structs MUST be byte-for-byte identical to types.rs
//              in ebpf-kern. They are used to read/write BPF map entries
//              from user-space via the aya Map API.
//
//              Verification: run `scripts/verify_abi.sh` to compare sizes
//              and offsets between kernel and user types.
// =============================================================================

use serde::{Deserialize, Serialize};

// ─── aya::Pod marker trait ────────────────────────────────────────────────────
// aya requires any value type stored in Array / PerCpuArray / HashMap maps to
// implement the `Pod` (Plain Old Data) marker trait. The contract is:
//   1) The type is `Copy + 'static` (enforced via supertrait bounds in aya).
//   2) The type has a fixed, well-defined byte layout (#[repr(C)] / no padding
//      that contains pointers or references).
//   3) Every bit pattern is a valid instance (no enums with niches, no Box).
//
// All five structs below satisfy these constraints: they are `#[repr(C)]`,
// `Copy + Clone`, contain only primitive integers and fixed-size byte padding,
// and are designed to be ABI-stable across the kernel↔user boundary.
//
// SAFETY: implementing `unsafe trait Pod` is a promise we uphold by construction.
unsafe impl aya::Pod for BlockEntry    {}
unsafe impl aya::Pod for RateBucket    {}
unsafe impl aya::Pod for XdpStats      {}
unsafe impl aya::Pod for FailsafeState {}
unsafe impl aya::Pod for FalxMapConfig {}

// ─── Block Entry ──────────────────────────────────────────────────────────────
/// Mirrors: ebpf-kern/src/types.rs :: BlockEntry
/// Must match: control-plane/internal/bpfmaps/types.go :: BlockEntry
#[repr(C)]
#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize)]
pub struct BlockEntry {
    pub expire_at:    u64,
    pub action:       u8,
    pub rule_id:      u8,
    pub threat_score: u8,
    pub _pad:         u8,
    pub reason:       u32,
}

// ─── Rate Bucket ──────────────────────────────────────────────────────────────
/// Mirrors: ebpf-kern/src/types.rs :: RateBucket
#[repr(C)]
#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize)]
pub struct RateBucket {
    pub tokens:      u64,
    pub last_refill: u64,
    pub capacity:    u64,
    pub refill_rate: u64,
    pub drop_count:  u64,
}

// ─── Per-CPU Stats ────────────────────────────────────────────────────────────
/// Mirrors: ebpf-kern/src/types.rs :: XdpStats
/// Aggregated across all CPUs by the control plane.
#[repr(C)]
#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize)]
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
    pub last_reset_ns:  u64,
}

/// Aggregated stats (sum across all CPUs)
impl std::ops::Add for XdpStats {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        XdpStats {
            rx_packets:     self.rx_packets.saturating_add(rhs.rx_packets),
            rx_bytes:       self.rx_bytes.saturating_add(rhs.rx_bytes),
            dropped:        self.dropped.saturating_add(rhs.dropped),
            rate_limited:   self.rate_limited.saturating_add(rhs.rate_limited),
            passed:         self.passed.saturating_add(rhs.passed),
            redirected:     self.redirected.saturating_add(rhs.redirected),
            failsafe_drops: self.failsafe_drops.saturating_add(rhs.failsafe_drops),
            parse_errors:   self.parse_errors.saturating_add(rhs.parse_errors),
            map_errors:     self.map_errors.saturating_add(rhs.map_errors),
            last_reset_ns:  self.last_reset_ns.max(rhs.last_reset_ns),
        }
    }
}

// ─── Failsafe State ───────────────────────────────────────────────────────────
/// Mirrors: ebpf-kern/src/types.rs :: FailsafeState
#[repr(C)]
#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize)]
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

// ─── Runtime Config ───────────────────────────────────────────────────────────
/// Mirrors: ebpf-kern/src/types.rs :: FalxMapConfig
#[repr(C)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
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

impl Default for FalxMapConfig {
    fn default() -> Self {
        FalxMapConfig {
            default_action:     1, // PASS
            rate_limit_enabled: 1,
            failsafe_enabled:   1,
            afxdp_redirect:     0,
            _pad:               [0u8; 4],
            rate_capacity:      1_000,
            rate_refill_ns:     1_000_000,
            honeypot_ip:        0,
            honeypot_port:      0,
            _pad2:              [0u8; 2],
        }
    }
}

// ─── Action Constants ─────────────────────────────────────────────────────────
pub mod action {
    pub const PASS:       u8 = 1;
    pub const DROP:       u8 = 2;
    pub const REDIRECT:   u8 = 3;
    pub const RATE_LIMIT: u8 = 4;
}

// ─── ABI Size Verification ────────────────────────────────────────────────────
// These assertions run at compile time. If sizes change due to struct
// modifications, this catches the mismatch immediately.
#[cfg(test)]
mod abi_tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn block_entry_size() {
        // 8 (expire_at) + 1 + 1 + 1 + 1 (pad) + 4 (reason) = 16 bytes
        assert_eq!(size_of::<BlockEntry>(), 16);
    }

    #[test]
    fn rate_bucket_size() {
        // 5 * 8 = 40 bytes
        assert_eq!(size_of::<RateBucket>(), 40);
    }

    #[test]
    fn xdp_stats_size() {
        // 10 * 8 = 80 bytes
        assert_eq!(size_of::<XdpStats>(), 80);
    }

    #[test]
    fn failsafe_state_size() {
        // 1 + 7 (pad) + 6*8 = 56 bytes
        assert_eq!(size_of::<FailsafeState>(), 56);
    }

    #[test]
    fn falx_map_config_size() {
        // 4 + 4 (pad) + 8 + 8 + 4 + 2 + 2 = 32 bytes
        assert_eq!(size_of::<FalxMapConfig>(), 32);
    }
}
