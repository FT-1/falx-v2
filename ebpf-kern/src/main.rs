// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: eBPF/XDP kernel-side drop pipeline (ebpf-kern/src/main.rs).
//              This is the CRITICAL HOT PATH — every packet on the wire
//              passes through this function.
//
//              Phase-11 Pipeline (in order):
//                [0]  Ethernet bounds pre-check — XDP_DROP on frames < 14 B
//                [1]  Parse Ethernet → IP → TCP/UDP (ptr_at bounds-checked)
//                [2]  Update MAPPED_XDP_STATS rx counters (per-CPU, lock-free)
//                [3]  Read runtime CONFIG map
//                [4]  Non-IP traffic → XDP_PASS immediately
//                [5]  Failsafe circuit breaker → XDP_DROP if OPEN
//                [6]  Bloom Filter pre-screen → skip LRU if IP definitely absent
//                [7]  BLOCKLIST_V4/V6 LRU lookup → XDP_DROP / XDP_REDIRECT
//                [7.5] SYN flood counter — per-source SYN/ACK ratio tracker
//                     ≥ 50 consecutive SYNs with 0 ACKs → max-penalty ban (r=8)
//                     Bypasses rate limiter; ACK packets reset the counter.
//                [8]  Token bucket rate limit → XDP_DROP if exhausted
//                     On DROP: apply_cooling_ban(min_r=0) [best-effort RMW]
//                [9]  SYN flood heuristic (10× token cost per SYN-only packet)
//                     On DROP: apply_cooling_ban(min_r=0) [best-effort RMW]
//               [10]  Update MAPPED_XDP_STATS passed counters
//               [11]  XDP_PASS
//
//              Phase-11 Security Hardening:
//
//                [F1-A] apply_cooling_ban: r computed as a LOCAL scalar from
//                  `prev` (read from map pointer into register) BEFORE any
//                  write-back to the map value. The BPF verifier scalar range
//                  tracker now sees r ∈ [1, 16] via branch analysis of the
//                  if/else clamp, proving the left-shift amount is bounded.
//                  No variable-shift with opaque-range operand.
//
//                Option B (Race-Tolerant): no bpf_spin_lock on COOLING_TRACKER.
//                  Eliminates the BTF requirement that caused verifier rejection.
//                  repeat_count RMW is best-effort under multi-CPU floods.
// =============================================================================

#![no_std]
#![no_main]

#![allow(dead_code)]
#![allow(static_mut_refs)]

#[used]
#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";

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
        Err(_)     => xdp_action::XDP_PASS,
    }
}

// ─── Main Packet Processing Pipeline ─────────────────────────────────────────
#[inline(always)]
fn process_packet(ctx: &XdpContext) -> Result<u32, u32> {

    // ── [0] Strict Fail-Closed Ethernet Bounds Pre-Check ─────────────────────
    // Drop any frame shorter than 14 bytes (minimum Ethernet header).
    // Fail-closed: legitimate Ethernet frames are always ≥ 14 bytes.
    {
        let data:     usize = ctx.data();
        let data_end: usize = ctx.data_end();
        if data.saturating_add(14) > data_end {
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // ── [1] Parse Headers ────────────────────────────────────────────────────
    let pkt = match parse_packet(ctx) {
        Ok(p)  => p,
        Err(_) => {
            bump_stat(|s| s.parse_errors = s.parse_errors.saturating_add(1));
            return Ok(xdp_action::XDP_DROP);
        }
    };

    // ── [2] Update MAPPED_XDP_STATS Rx Counters ───────────────────────────────
    bump_mapped(|m| {
        m.rx_packets = m.rx_packets.saturating_add(1);
        m.rx_bytes   = m.rx_bytes.saturating_add(pkt.pkt_len as u64);
    });

    // ── [3] Read Runtime Config ────────────────────────────────────────────────
    let cfg = read_config();

    // ── [4] Non-IP → PASS ────────────────────────────────────────────────────
    if pkt.src_ip == 0 && !pkt.is_ipv6 {
        bump_mapped(|m| {
            m.passed       = m.passed.saturating_add(1);
            m.passed_bytes = m.passed_bytes.saturating_add(pkt.pkt_len as u64);
        });
        return Ok(xdp_action::XDP_PASS);
    }

    // ── [5] Failsafe Circuit Breaker ─────────────────────────────────────────
    if cfg.failsafe_enabled != 0 {
        if let Some(verdict) = check_failsafe(&pkt) {
            if verdict == xdp_action::XDP_DROP {
                bump_mapped(|m| {
                    m.dropped       = m.dropped.saturating_add(1);
                    m.dropped_bytes = m.dropped_bytes.saturating_add(pkt.pkt_len as u64);
                });
            }
            return Ok(verdict);
        }
    }

    // ── [6 + 7] Bloom Filter Pre-Screen → BLOCKLIST Lookup ───────────────────
    if !pkt.is_ipv6 {
        let needs_lru_check = unsafe {
            BLOOM_FILTER.contains(&pkt.src_ip)
        }.is_ok();

        if needs_lru_check {
            if let Some(verdict) = check_blocklist_v4(ctx, pkt.src_ip) {
                if verdict == xdp_action::XDP_DROP {
                    bump_mapped(|m| {
                        m.dropped       = m.dropped.saturating_add(1);
                        m.dropped_bytes = m.dropped_bytes.saturating_add(pkt.pkt_len as u64);
                    });
                }
                return Ok(verdict);
            }
        }
    } else {
        if let Some(verdict) = check_blocklist_v6(pkt.src_ip6) {
            if verdict == xdp_action::XDP_DROP {
                bump_mapped(|m| {
                    m.dropped       = m.dropped.saturating_add(1);
                    m.dropped_bytes = m.dropped_bytes.saturating_add(pkt.pkt_len as u64);
                });
            }
            return Ok(verdict);
        }
    }

    // ── [7.5] SYN Flood Counter (IPv4 TCP only — BEFORE rate limiter) ────────
    // Tracks consecutive SYN-only packets per source. ACK packets reset the
    // counter. When a source sends ≥ 50 SYNs with zero completing ACKs, it is
    // immediately banned at max-penalty (r ≥ 8, T_ban ≥ 2 560 s) without going
    // through the token bucket — the source never gets to consume rate-limit
    // capacity and cannot probe the rate-limit boundary.
    if pkt.protocol == proto::TCP && !pkt.is_ipv6 {
        let now_ns_syn = unsafe { bpf_ktime_get_ns() };
        if let Some(verdict) = check_syn_counter(pkt.src_ip, pkt.tcp_flags, now_ns_syn) {
            bump_mapped(|m| {
                m.dropped       = m.dropped.saturating_add(1);
                m.dropped_bytes = m.dropped_bytes.saturating_add(pkt.pkt_len as u64);
            });
            return Ok(verdict);
        }
    }

    // ── [8] Token Bucket Rate Limiter ─────────────────────────────────────────
    if cfg.rate_limit_enabled != 0 && !pkt.is_ipv6 {
        if let Some(verdict) = check_rate_limit(pkt.src_ip, &cfg) {
            bump_stat(|s| s.rate_limited = s.rate_limited.saturating_add(1));
            return Ok(verdict);
        }
    }

    // ── [9] SYN Flood Heuristic ───────────────────────────────────────────────
    if pkt.protocol == proto::TCP
        && parser::tcp_flags::is_syn_only(pkt.tcp_flags)
        && cfg.rate_limit_enabled != 0
        && !pkt.is_ipv6
    {
        if let Some(verdict) = check_syn_flood(pkt.src_ip) {
            bump_stat(|s| s.rate_limited = s.rate_limited.saturating_add(1));
            return Ok(verdict);
        }
    }

    // ── [10+11] Update Passed Counter and PASS ────────────────────────────────
    bump_mapped(|m| {
        m.passed       = m.passed.saturating_add(1);
        m.passed_bytes = m.passed_bytes.saturating_add(pkt.pkt_len as u64);
    });
    Ok(xdp_action::XDP_PASS)
}

// ─── [5] Failsafe / Circuit Breaker ──────────────────────────────────────────
#[inline(always)]
fn check_failsafe(pkt: &parser::PacketInfo) -> Option<u32> {
    if let Some(s) = unsafe { FAILSAFE_STATE.get_ptr_mut(FAILSAFE_IDX) } {
        let now_ns = unsafe { bpf_ktime_get_ns() };
        unsafe {
            let elapsed = now_ns.saturating_sub((*s).window_start_ns);
            if elapsed >= 1_000_000_000 {
                (*s).current_pps     = 1;
                (*s).current_bps     = pkt.pkt_len as u64 * 8;
                (*s).window_start_ns = now_ns;
            } else {
                (*s).current_pps = (*s).current_pps.saturating_add(1);
                (*s).current_bps = (*s).current_bps
                    .saturating_add(pkt.pkt_len as u64 * 8);
            }

            if (*s).circuit_open == 0 && (
                (*s).current_pps > (*s).pps_threshold ||
                (*s).current_bps > (*s).bps_threshold
            ) {
                (*s).circuit_open  = 1;
                (*s).open_since_ns = now_ns;
            }

            if (*s).circuit_open != 0 {
                bump_stat(|st| {
                    st.failsafe_drops = st.failsafe_drops.saturating_add(1);
                });
                return Some(xdp_action::XDP_DROP);
            }
        }
    }
    None
}

// ─── [7a] Blocklist IPv4 ─────────────────────────────────────────────────────
#[inline(always)]
fn check_blocklist_v4(ctx: &XdpContext, src_ip: u32) -> Option<u32> {
    let entry = unsafe { BLOCKLIST_V4.get(&src_ip)? };

    if entry.expire_at != 0 {
        let now_s = unsafe { bpf_ktime_get_ns() } / 1_000_000_000;
        if now_s >= entry.expire_at {
            return None;
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

// ─── [7b] Blocklist IPv6 ─────────────────────────────────────────────────────
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

// ─── [8] Token Bucket Rate Limiter ───────────────────────────────────────────
#[inline(always)]
fn check_rate_limit(src_ip: u32, cfg: &FalxMapConfig) -> Option<u32> {
    let now_ns = unsafe { bpf_ktime_get_ns() };

    match unsafe { RATE_LIMIT.get_ptr_mut(&src_ip) } {
        Some(bucket) => unsafe {
            let elapsed    = now_ns.saturating_sub((*bucket).last_refill);
            let refill_amt = elapsed
                .checked_div((*bucket).refill_rate)
                .unwrap_or(0);

            if refill_amt > 0 {
                (*bucket).tokens = (*bucket).tokens
                    .saturating_add(refill_amt)
                    .min((*bucket).capacity);
                (*bucket).last_refill = now_ns;
            }

            if (*bucket).tokens == 0 {
                (*bucket).drop_count = (*bucket).drop_count.saturating_add(1);
                apply_cooling_ban(src_ip, now_ns, 0);
                return Some(xdp_action::XDP_DROP);
            }
            (*bucket).tokens -= 1;
            None
        },
        None => {
            let bucket = RateBucket {
                tokens:      cfg.rate_capacity.saturating_sub(1),
                last_refill: now_ns,
                capacity:    cfg.rate_capacity,
                refill_rate: cfg.rate_refill_ns,
                drop_count:  0,
            };
            let _ = unsafe { RATE_LIMIT.insert(&src_ip, &bucket, 0) };
            None
        }
    }
}

// ─── [9] SYN Flood Heuristic ─────────────────────────────────────────────────
#[inline(always)]
fn check_syn_flood(src_ip: u32) -> Option<u32> {
    match unsafe { RATE_LIMIT.get_ptr_mut(&src_ip) } {
        Some(bucket) => unsafe {
            if (*bucket).tokens < 10 {
                (*bucket).drop_count = (*bucket).drop_count.saturating_add(1);
                let now_ns = bpf_ktime_get_ns();
                apply_cooling_ban(src_ip, now_ns, 0);
                return Some(xdp_action::XDP_DROP);
            }
            (*bucket).tokens -= 10;
            None
        },
        None => None,
    }
}

// ─── [7.5] SYN Flood Counter ─────────────────────────────────────────────────
//
// Tracks SYN-to-ACK ratio per source IP using the SYN_COUNTER LRU map.
//
// On SYN-only packet: increment syn_count. If syn_count ≥ SYN_FLOOD_THRESHOLD
//   AND ack_count == 0: issue max-penalty ban (min_r = SYN_FLOOD_PENALTY_R = 8),
//   reset syn_count so the counter re-arms for the next burst, return XDP_DROP.
//
// On ACK (non-SYN) packet: reset syn_count to 0, increment ack_count. Return
//   None so the packet proceeds normally.
//
// The ACK check uses raw flag bits (ACK=0x10, SYN=0x02) via parser::tcp_flags.
#[inline(always)]
fn check_syn_counter(src_ip: u32, tcp_flags: u8, now_ns: u64) -> Option<u32> {
    use parser::tcp_flags::{ACK, SYN};

    // ACK without SYN = handshake completion or established-session data.
    // Reset the SYN flood counter for this source — it completed a handshake.
    if tcp_flags & ACK != 0 && tcp_flags & SYN == 0 {
        if let Some(entry) = unsafe { SYN_COUNTER.get_ptr_mut(&src_ip) } {
            unsafe {
                (*entry).syn_count = 0;
                (*entry).ack_count = (*entry).ack_count.saturating_add(1);
            }
        }
        return None;
    }

    // Only act on SYN-only packets from here.
    if !parser::tcp_flags::is_syn_only(tcp_flags) {
        return None;
    }

    match unsafe { SYN_COUNTER.get_ptr_mut(&src_ip) } {
        Some(entry) => unsafe {
            let syn = (*entry).syn_count.saturating_add(1);
            (*entry).syn_count = syn;

            if syn >= SYN_FLOOD_THRESHOLD && (*entry).ack_count == 0 {
                // ≥ 50 consecutive SYNs, zero ACKs: SYN flood confirmed.
                // Bypass rate limiter; issue max-penalty ban directly.
                apply_cooling_ban(src_ip, now_ns, SYN_FLOOD_PENALTY_R);
                bump_stat(|s| s.syn_flood_bans = s.syn_flood_bans.saturating_add(1));
                // Reset counter so it re-arms for the next burst from this source.
                (*entry).syn_count = 0;
                Some(xdp_action::XDP_DROP)
            } else {
                None
            }
        },
        None => {
            // First SYN from this source — insert with count = 1.
            let fresh = SynCountEntry { syn_count: 1, ack_count: 0 };
            let _ = unsafe { SYN_COUNTER.insert(&src_ip, &fresh, 0) };
            None
        }
    }
}

// ─── Exponential Backoff Cooling State Machine ────────────────────────────────
//
// min_r: minimum repeat_count to enforce. Normal callers pass 0 (no floor).
// SYN flood path passes SYN_FLOOD_PENALTY_R (8), guaranteeing T_ban ≥ 2 560 s
// even on first offense, without relying on prior cooling history.
//
// [F1-A] Verifier scalar range proof:
//   min_r is clamped to [0, 16] via an if/else before any use. After:
//     r_nat ∈ [1, 16]  (from if/else on prev)
//     min_r_c ∈ [0, 16] (from clamp)
//     r = max(r_nat, min_r_c) ∈ [0, 16]  (both arms bounded)
//   `COOLING_BASE_S << r` with r ∈ [0, 16] → max 655 360 — verifier-provable.
//   None arm: r = min_r_c ∈ [0, 16] — same proof.
//
// Option B: no bpf_spin_lock. RMW is best-effort under multi-CPU floods.
// Every path still writes a correct timed BLOCKLIST_V4 entry.
//
// #[inline(never)] isolates this from the fast-path icache window.
#[inline(never)]
fn apply_cooling_ban(src_ip: u32, now_ns: u64, min_r: u32) {
    let now_s = now_ns / 1_000_000_000;

    // Clamp min_r to [0, MAX_COOLING_SHIFT]. After this if/else the verifier
    // knows min_r_c ∈ [0, 16] and propagates the range into both match arms.
    let min_r_c = if min_r <= MAX_COOLING_SHIFT { min_r } else { MAX_COOLING_SHIFT };

    // ── Update existing COOLING_TRACKER entry (best-effort RMW) ─────────────
    let (r, ban_secs) = match unsafe { COOLING_TRACKER.get_ptr_mut(&src_ip) } {
        Some(entry) => unsafe {
            // [F1-A] Read into local scalar; branch proves r_nat ∈ [1, 16].
            let prev  = (*entry).repeat_count;
            let r_nat = if prev < MAX_COOLING_SHIFT { prev + 1 } else { MAX_COOLING_SHIFT };
            // Apply minimum penalty floor. Both arms verifier-bounded ∈ [0, 16].
            let r   = if r_nat > min_r_c { r_nat } else { min_r_c };
            let ban = COOLING_BASE_S << r;  // r ∈ [0,16] — bounded shift
            (*entry).repeat_count   = r;
            (*entry).last_ban_at_ns = now_ns;
            (r, ban)
        },
        None => {
            // Fresh source: start at min_r_c (0 for normal path, 8 for SYN flood).
            let r   = min_r_c;              // ∈ [0, 16] — proven by clamp above
            let ban = COOLING_BASE_S << r;  // bounded shift
            let fresh = CoolingEntry {
                repeat_count:   r,
                _pad:           0,
                last_ban_at_ns: now_ns,
            };
            let _ = unsafe { COOLING_TRACKER.insert(&src_ip, &fresh, 0) };
            (r, ban)
        }
    };

    // ── Write timed block entry into BLOCKLIST_V4 ─────────────────────────────
    let expire_at = now_s.saturating_add(ban_secs);
    let block = BlockEntry {
        expire_at,
        action:       action::DROP,
        rule_id:      0xFF,
        threat_score: (r.min(100)) as u8,
        _pad:         0,
        reason:       reason::COOLING_BAN,
    };
    let _ = unsafe { BLOCKLIST_V4.insert(&src_ip, &block, 0) };

    // ── Gate next packet at Bloom filter ─────────────────────────────────────
    let _ = unsafe { BLOOM_FILTER.insert(&src_ip, 0) };

    // ── Extended stat bump ────────────────────────────────────────────────────
    bump_stat(|s| s.cooling_bans = s.cooling_bans.saturating_add(1));
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

// ─── Compact Stats Helper (MAPPED_XDP_STATS — hot path) ──────────────────────
#[inline(always)]
fn bump_mapped<F: Fn(&mut MappedXdpStats)>(f: F) {
    if let Some(m) = unsafe { MAPPED_XDP_STATS.get_ptr_mut(MAPPED_STATS_IDX) } {
        unsafe { f(&mut *m) };
    }
}

// ─── Full Stats Helper (XDP_STATS — extended/cold path) ──────────────────────
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
