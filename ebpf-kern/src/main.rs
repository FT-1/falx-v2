// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: eBPF/XDP kernel-side drop pipeline (ebpf-kern/src/main.rs).
//              This is the CRITICAL HOT PATH — every packet on the wire
//              passes through this function. Design goals:
//
//              1. SPEED:        < 1µs average decision @ 10 Gbps line rate
//              2. SAFETY:       All memory accesses verifier-validated
//              3. RESILIENCE:   Failsafe circuit breaker for DDoS floods
//              4. EXTENSIBILITY: Maps ready for AI verdict injection (Phase 9)
//
//              Pipeline (in order):
//                [1] Parse Ethernet → IP → TCP/UDP (bounds-checked)
//                [2] Non-IP traffic → XDP_PASS immediately
//                [3] Update per-CPU stats (lock-free)
//                [4] Check CONFIG map for runtime policy
//                [5] Failsafe circuit breaker → XDP_DROP if circuit OPEN
//                [6] BLOCKLIST_V4/V6 lookup → XDP_DROP if blocked
//                [7] Token bucket rate limit → XDP_DROP if exhausted
//                [8] SYN flood heuristic → extra token cost
//                [9] XDP_PASS — clean packet to network stack
// =============================================================================

#![no_std]
#![no_main]

// ─── Crate-level lint configuration ──────────────────────────────────────────
// `dead_code`: types.rs and parser.rs define a number of constants/helpers
// (action::RATE_LIMIT, reason::*, proto::ICMP/ICMPV6/ARP, tcp_flags::*,
// ntohl/htonl, is_syn_ack) that are reserved for Phase 9+ (AI verdict path
// and TCP-flag-based heuristics). They are intentional, not stale code.
//
// `static_mut_refs`: Aya's `#[map]` proc-macro generates `pub static mut MAP`
// declarations, and `unsafe { MAP.get(...) }` is the documented API for
// reading them. The Rust 2024 compatibility lint flags this pattern as
// dangerous in general, but for BPF map handles the kernel verifier
// enforces safety — there are no mutable references on the user-visible
// side. Aya is tracking the 2024-edition migration upstream; until then
// we silence the lint at crate level.
#![allow(dead_code)]
#![allow(static_mut_refs)]

mod types;
mod maps;
mod parser;
mod honeypot;
mod honeypot_maps;

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::xdp,
    programs::XdpContext,
};

use maps::*;
use types::*;
use parser::parse_packet;
use honeypot::redirect_to_honeypot;

// ─── XDP Entry Point ──────────────────────────────────────────────────────────
#[xdp]
pub fn falx_xdp(ctx: XdpContext) -> u32 {
    match process_packet(&ctx) {
        Ok(action) => action,
        Err(_)     => xdp_action::XDP_PASS,  // Fail-open on internal error
    }
}

// ─── Main Packet Processing Pipeline ─────────────────────────────────────────
#[inline(always)]
fn process_packet(ctx: &XdpContext) -> Result<u32, u32> {

    // ── [1] Parse Headers ────────────────────────────────────────────────────
    let pkt = match parse_packet(ctx) {
        Ok(p)  => p,
        Err(_) => {
            bump_stat(|s| s.parse_errors += 1);
            return Ok(xdp_action::XDP_PASS);
        }
    };

    // ── [2] Update Rx Stats ───────────────────────────────────────────────────
    bump_stat(|s| {
        s.rx_packets = s.rx_packets.saturating_add(1);
        s.rx_bytes   = s.rx_bytes.saturating_add(pkt.pkt_len as u64);
    });

    // ── [3] Read Runtime Config ────────────────────────────────────────────────
    let cfg = read_config();

    // ── [4] Non-IP → PASS ────────────────────────────────────────────────────
    if pkt.src_ip == 0 && !pkt.is_ipv6 {
        bump_stat(|s| s.passed = s.passed.saturating_add(1));
        return Ok(xdp_action::XDP_PASS);
    }

    // ── [5] Failsafe Circuit Breaker ─────────────────────────────────────────
    if cfg.failsafe_enabled != 0 {
        if let Some(verdict) = check_failsafe(&pkt) {
            return Ok(verdict);
        }
    }

    // ── [6] Blocklist ─────────────────────────────────────────────────────────
    if !pkt.is_ipv6 {
        if let Some(verdict) = check_blocklist_v4(ctx, pkt.src_ip) {
            return Ok(verdict);
        }
    } else {
        if let Some(verdict) = check_blocklist_v6(pkt.src_ip6) {
            return Ok(verdict);
        }
    }

    // ── [7] Rate Limit ────────────────────────────────────────────────────────
    if cfg.rate_limit_enabled != 0 && !pkt.is_ipv6 {
        if let Some(verdict) = check_rate_limit(pkt.src_ip, &cfg) {
            return Ok(verdict);
        }
    }

    // ── [8] SYN Flood Heuristic ───────────────────────────────────────────────
    if pkt.protocol == proto::TCP
        && parser::tcp_flags::is_syn_only(pkt.tcp_flags)
        && cfg.rate_limit_enabled != 0
        && !pkt.is_ipv6
    {
        if let Some(verdict) = check_syn_flood(pkt.src_ip) {
            return Ok(verdict);
        }
    }

    // ── [9] PASS ──────────────────────────────────────────────────────────────
    bump_stat(|s| s.passed = s.passed.saturating_add(1));
    Ok(xdp_action::XDP_PASS)
}

// ─── [5] Failsafe / Circuit Breaker ──────────────────────────────────────────
#[inline(always)]
fn check_failsafe(pkt: &parser::PacketInfo) -> Option<u32> {
    // Update rolling counters
    if let Some(s) = unsafe { FAILSAFE_STATE.get_ptr_mut(FAILSAFE_IDX) } {
        let now_ns = unsafe { bpf_ktime_get_ns() };
        unsafe {
            let elapsed = now_ns.saturating_sub((*s).window_start_ns);
            if elapsed >= 1_000_000_000 {
                // Reset 1-second window
                (*s).current_pps     = 1;
                (*s).current_bps     = pkt.pkt_len as u64 * 8;
                (*s).window_start_ns = now_ns;
            } else {
                (*s).current_pps = (*s).current_pps.saturating_add(1);
                (*s).current_bps = (*s).current_bps.saturating_add(pkt.pkt_len as u64 * 8);
            }

            // XDP autonomously opens circuit when thresholds exceeded
            if (*s).circuit_open == 0 && (
                (*s).current_pps > (*s).pps_threshold ||
                (*s).current_bps > (*s).bps_threshold
            ) {
                (*s).circuit_open  = 1;
                (*s).open_since_ns = now_ns;
            }

            if (*s).circuit_open != 0 {
                bump_stat(|st| st.failsafe_drops = st.failsafe_drops.saturating_add(1));
                return Some(xdp_action::XDP_DROP);
            }
        }
    }
    None
}

// ─── [6a] Blocklist IPv4 ─────────────────────────────────────────────────────
#[inline(always)]
fn check_blocklist_v4(ctx: &XdpContext, src_ip: u32) -> Option<u32> {
    let entry = unsafe { BLOCKLIST_V4.get(&src_ip)? };

    // Check TTL expiry
    if entry.expire_at != 0 {
        let now_s = unsafe { bpf_ktime_get_ns() } / 1_000_000_000;
        if now_s >= entry.expire_at {
            return None; // Expired — fail open, CP cleans up async
        }
    }

    match entry.action {
        a if a == action::DROP => {
            bump_stat(|s| s.dropped = s.dropped.saturating_add(1));
            Some(xdp_action::XDP_DROP)
        }
        a if a == action::REDIRECT => {
            bump_stat(|s| s.redirected = s.redirected.saturating_add(1));
            Some(redirect_to_honeypot(ctx))
        }
        _ => None,
    }
}

// ─── [6b] Blocklist IPv6 ─────────────────────────────────────────────────────
#[inline(always)]
fn check_blocklist_v6(src_ip6: [u8; 16]) -> Option<u32> {
    let entry = unsafe { BLOCKLIST_V6.get(&src_ip6)? };

    if entry.expire_at != 0 {
        let now_s = unsafe { bpf_ktime_get_ns() } / 1_000_000_000;
        if now_s >= entry.expire_at {
            return None;
        }
    }

    if entry.action == action::DROP {
        bump_stat(|s| s.dropped = s.dropped.saturating_add(1));
        Some(xdp_action::XDP_DROP)
    } else {
        None
    }
}

// ─── [7] Token Bucket Rate Limiter ───────────────────────────────────────────
#[inline(always)]
fn check_rate_limit(src_ip: u32, cfg: &FalxMapConfig) -> Option<u32> {
    let now_ns = unsafe { bpf_ktime_get_ns() };

    match unsafe { RATE_LIMIT.get_ptr_mut(&src_ip) } {
        Some(bucket) => unsafe {
            // Calculate elapsed time and refill tokens
            let elapsed    = now_ns.saturating_sub((*bucket).last_refill);
            let refill_amt = elapsed / (*bucket).refill_rate;

            if refill_amt > 0 {
                (*bucket).tokens = (*bucket).tokens
                    .saturating_add(refill_amt)
                    .min((*bucket).capacity);
                (*bucket).last_refill = now_ns;
            }

            // Attempt to consume 1 token
            if (*bucket).tokens == 0 {
                (*bucket).drop_count = (*bucket).drop_count.saturating_add(1);
                bump_stat(|s| s.rate_limited = s.rate_limited.saturating_add(1));
                return Some(xdp_action::XDP_DROP);
            }
            (*bucket).tokens -= 1;
            None
        },
        None => {
            // First packet from this source: create bucket
            let bucket = RateBucket {
                tokens:      cfg.rate_capacity.saturating_sub(1),
                last_refill: now_ns,
                capacity:    cfg.rate_capacity,
                refill_rate: cfg.rate_refill_ns,
                drop_count:  0,
            };
            // Fail-open if map insert fails (map full)
            let _ = unsafe { RATE_LIMIT.insert(&src_ip, &bucket, 0) };
            None
        }
    }
}

// ─── [8] SYN Flood Heuristic ─────────────────────────────────────────────────
/// SYN packets cost 10 tokens each (10x normal cost).
/// This provides amplified early detection of SYN floods before the
/// per-second rate limit would normally trigger.
#[inline(always)]
fn check_syn_flood(src_ip: u32) -> Option<u32> {
    match unsafe { RATE_LIMIT.get_ptr_mut(&src_ip) } {
        Some(bucket) => unsafe {
            if (*bucket).tokens < 10 {
                (*bucket).drop_count = (*bucket).drop_count.saturating_add(1);
                bump_stat(|s| s.rate_limited = s.rate_limited.saturating_add(1));
                return Some(xdp_action::XDP_DROP);
            }
            (*bucket).tokens -= 10;
            None
        },
        None => None, // New source: allow first SYN
    }
}

// ─── Config Reader ────────────────────────────────────────────────────────────
#[inline(always)]
fn read_config() -> FalxMapConfig {
    match unsafe { CONFIG.get(CONFIG_IDX) } {
        Some(c) => *c,
        None    => FalxMapConfig {
            default_action:     action::PASS,
            rate_limit_enabled: 1,
            failsafe_enabled:   1,
            afxdp_redirect:     0,
            _pad:               [0u8; 4],
            rate_capacity:      1_000,
            rate_refill_ns:     1_000_000,
            honeypot_ip:        0,
            honeypot_port:      0,
            _pad2:              [0u8; 2],
        },
    }
}

// ─── Stats Helper ─────────────────────────────────────────────────────────────
#[inline(always)]
fn bump_stat<F: Fn(&mut XdpStats)>(f: F) {
    if let Some(stats) = unsafe { XDP_STATS.get_ptr_mut(STATS_IDX) } {
        unsafe { f(&mut *stats) };
    }
}

// ─── BPF Panic Handler ────────────────────────────────────────────────────────
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
