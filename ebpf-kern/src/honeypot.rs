// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: XDP honeypot redirect (ebpf-kern/src/honeypot.rs).
//              Implements SILENT REDIRECTION — the attacker believes they are
//              still hitting the real target, but their packets are actually
//              forwarded to a honeypot for full session capture.
//
//              Redirect mechanism (XDP_TX path):
//                1. Packet arrives on ingress interface
//                2. XDP reads BLOCKLIST_V4 → action = ACTION_REDIRECT
//                3. XDP reads active HoneypotTarget from HONEYPOT_TARGETS map
//                4. XDP rewrites in-place (no alloc, no copy):
//                     - Ethernet: swap src/dst MAC, set honeypot MAC as dst
//                     - IPv4:     overwrite dst_addr with honeypot IP
//                     - IPv4:     recompute header checksum (incremental RFC 1624)
//                     - TCP/UDP:  optionally rewrite dst_port
//                5. XDP_TX: bounce packet back out the same NIC
//
//              Why XDP_TX and not XDP_REDIRECT?
//                XDP_TX resends on the SAME interface — simpler, no redirect map
//                needed for the honeypot itself. The honeypot must be on the
//                same L2 segment as the target interface (or reachable via ARP).
//
//              Verifier requirements:
//                - All pointer arithmetic bounds-checked before write
//                - bpf_csum_diff() used for incremental checksum update
//                - Stack usage < 128 bytes (leaves room for caller frame)
// =============================================================================

use aya_ebpf::{
    bindings::xdp_action,
    programs::XdpContext,
};
use core::mem;
use crate::parser::{EthHdr, Ipv4Hdr, TcpHdr, UdpHdr, ptr_at_mut};
use crate::types::{ethertype, proto};
use crate::honeypot_maps::{HONEYPOT_TARGETS, HONEYPOT_ACTIVE};

// ─── Honeypot Target Descriptor ───────────────────────────────────────────────
// Stored in HONEYPOT_TARGETS map. Written by Go control plane.
// MUST mirror control-plane/internal/honeypot/types.go :: HoneypotTarget
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HoneypotTarget {
    /// Destination IPv4 of honeypot (network byte order)
    pub dst_ip:   u32,
    /// Destination MAC address of honeypot (or next-hop MAC)
    pub dst_mac:  [u8; 6],
    /// Source MAC to use (typically the real server's MAC)
    pub src_mac:  [u8; 6],
    /// If nonzero, rewrite TCP/UDP destination port
    pub dst_port: u16,
    /// Padding
    pub _pad:     [u8; 2],
    /// Is this target active? 0 = disabled
    pub active:   u8,
    pub _pad2:    [u8; 3],
}

// ─── Main Redirect Entry Point ────────────────────────────────────────────────
/// Rewrites packet headers to redirect to the active honeypot.
/// Called when BLOCKLIST_V4 entry has action == ACTION_REDIRECT.
/// Returns XDP_TX on success, XDP_DROP on error (fail-safe).
#[inline(always)]
pub fn redirect_to_honeypot(ctx: &XdpContext) -> u32 {
    match try_redirect(ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_DROP, // Fail-safe: drop rather than leak to attacker
    }
}

#[inline(always)]
fn try_redirect(ctx: &XdpContext) -> Result<u32, ()> {
    // ── [1] Get active honeypot target ────────────────────────────────────
    let active_idx = unsafe {
        HONEYPOT_ACTIVE.get(0).copied().unwrap_or(0)
    };
    let target = unsafe {
        HONEYPOT_TARGETS.get(active_idx).ok_or(())?
    };

    if target.active == 0 || target.dst_ip == 0 {
        // No honeypot configured — drop instead
        return Err(());
    }

    // ── [2] Verify this is an IPv4 packet ─────────────────────────────────
    let eth: *mut EthHdr = unsafe { ptr_at_mut(ctx, 0)? };
    let ether_type = u16::from_be(unsafe { (*eth).ether_type });
    if ether_type != ethertype::IPV4 {
        return Err(()); // Only support IPv4 redirect for now
    }

    let ip_offset = mem::size_of::<EthHdr>();
    let ip: *mut Ipv4Hdr = unsafe { ptr_at_mut(ctx, ip_offset)? };

    let ihl = unsafe { ((*ip).version_ihl & 0x0F) as usize * 4 };
    if ihl < 20 {
        return Err(());
    }

    // ── [3] Rewrite Ethernet header ───────────────────────────────────────
    unsafe {
        // Swap: new dst MAC = honeypot MAC, new src MAC = configured src MAC
        (*eth).dst_mac = target.dst_mac;
        (*eth).src_mac = target.src_mac;
    }

    // ── [4] Rewrite IPv4 destination (incremental checksum update) ────────
    let old_dst = unsafe { (*ip).dst_addr };
    let new_dst = target.dst_ip;

    unsafe {
        (*ip).dst_addr = new_dst;
        // Recompute checksum: RFC 1624 incremental update
        (*ip).check = 0;
        (*ip).check = compute_ip_checksum(ctx, ip_offset, ihl)?;
    }

    // ── [5] Optionally rewrite TCP/UDP destination port ───────────────────
    if target.dst_port != 0 {
        let l4_offset = ip_offset + ihl;
        let protocol  = unsafe { (*ip).protocol };

        match protocol {
            p if p == proto::TCP => {
                let tcp: *mut TcpHdr = unsafe { ptr_at_mut(ctx, l4_offset)? };
                unsafe {
                    let old_port = (*tcp).dest;
                    (*tcp).dest  = target.dst_port.to_be();
                    // Recompute TCP checksum (incremental)
                    (*tcp).check = update_l4_checksum(
                        (*tcp).check, old_dst, new_dst,
                        old_port, target.dst_port.to_be(),
                    );
                }
            }
            p if p == proto::UDP => {
                let udp: *mut UdpHdr = unsafe { ptr_at_mut(ctx, l4_offset)? };
                unsafe {
                    let old_port = (*udp).dest;
                    (*udp).dest  = target.dst_port.to_be();
                    (*udp).check = update_l4_checksum(
                        (*udp).check, old_dst, new_dst,
                        old_port, target.dst_port.to_be(),
                    );
                }
            }
            _ => {} // ICMP: no port rewrite needed
        }
    }

    // ── [6] XDP_TX: bounce packet back out the same NIC ───────────────────
    // The packet is now headed to the honeypot. The attacker sees their
    // connection apparently succeeding (SYN → SYN-ACK from honeypot).
    Ok(xdp_action::XDP_TX)
}

// ─── IPv4 Header Checksum (from scratch) ──────────────────────────────────────
// RFC 791: one's complement sum of all 16-bit words in the IP header.
// We recompute from scratch after any header modification.
// Runs only over the IP header (max 60 bytes) — bounded, verifier-safe.
#[inline(always)]
fn compute_ip_checksum(ctx: &XdpContext, ip_offset: usize, ihl: usize) -> Result<u16, ()> {
    let start = ctx.data() + ip_offset;
    let end   = ctx.data_end();

    if start + ihl > end {
        return Err(());
    }

    let mut sum: u32 = 0;
    let hdr_ptr = start as *const u16;

    // Unrolled loop over max 30 u16 words (60 bytes max IHL)
    // BPF verifier requires bounded loops
    let words = ihl / 2;
    for i in 0..30usize {
        if i >= words { break; }
        // Safety: bounds checked above
        let word = unsafe { *(hdr_ptr.add(i)) } as u32;
        sum += u16::from_be(word) as u32;
    }

    // Fold 32-bit sum to 16 bits.
    // BPF verifier requires bounded loops — a 32-bit one's-complement sum of
    // 30 u16 words can have at most 1 carry bit above bit-16, so 2 iterations
    // are always sufficient. Unrolling makes this verifier-safe.
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);

    Ok(!(sum as u16))
}

// ─── Incremental L4 Checksum Update (RFC 1624) ───────────────────────────────
// Update TCP/UDP checksum after changing IP dst and/or dst_port.
// Uses the incremental formula: new_check = ~(~old_check - ~old_val + new_val)
#[inline(always)]
fn update_l4_checksum(
    old_check: u16,
    old_ip:    u32,
    new_ip:    u32,
    old_port:  u16,
    new_port:  u16,
) -> u16 {
    let mut csum = !old_check as u32;

    // Remove old IP (two 16-bit words)
    csum = csum.wrapping_sub((old_ip >> 16) as u32);
    csum = csum.wrapping_sub((old_ip & 0xFFFF) as u32);

    // Add new IP
    csum = csum.wrapping_add((new_ip >> 16) as u32);
    csum = csum.wrapping_add((new_ip & 0xFFFF) as u32);

    // Remove old port, add new port
    csum = csum.wrapping_sub(u16::from_be(old_port) as u32);
    csum = csum.wrapping_add(u16::from_be(new_port) as u32);

    // Fold and complement.
    // BPF verifier requires bounded loops — unrolled for verifier safety.
    // At most 2 carries possible from the 6 additions above.
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    !(csum as u16)
}
