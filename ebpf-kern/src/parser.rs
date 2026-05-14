// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Packet header parser (ebpf-kern/src/parser.rs).
//              All parsing is bounds-checked against ctx.data_end() BEFORE
//              any memory access. This is the #1 requirement of the BPF
//              verifier. Any violation causes program rejection at load time.
//
//              Design principles:
//              - Every ptr dereference preceded by a bounds check
//              - #[inline(always)] on all hot-path functions to avoid
//                BPF-to-BPF call overhead and verifier complexity
//              - No dynamic dispatch, no trait objects, no heap allocation
//              - Stack usage kept under 256 bytes to leave room for callers
//                (BPF stack limit is 512 bytes total)
// =============================================================================

use aya_ebpf::programs::XdpContext;
use core::mem;
use crate::types::{ethertype, proto};

// ─── Wire Header Layouts ──────────────────────────────────────────────────────
// All fields in NETWORK byte order (big-endian).
// repr(C, packed) prevents compiler from inserting padding.

#[repr(C, packed)]
pub struct EthHdr {
    pub dst_mac:    [u8; 6],
    pub src_mac:    [u8; 6],
    pub ether_type: u16,   // big-endian
}

#[repr(C, packed)]
pub struct Ipv4Hdr {
    pub version_ihl:    u8,   // version(4) + IHL(4)
    pub tos:            u8,
    pub tot_len:        u16,  // big-endian
    pub id:             u16,
    pub frag_off:       u16,
    pub ttl:            u8,
    pub protocol:       u8,
    pub check:          u16,
    pub src_addr:       u32,  // network byte order
    pub dst_addr:       u32,
}

#[repr(C, packed)]
pub struct Ipv6Hdr {
    pub version_tc_flow: u32,
    pub payload_len:     u16,
    pub next_hdr:        u8,
    pub hop_limit:       u8,
    pub src_addr:        [u8; 16],
    pub dst_addr:        [u8; 16],
}

#[repr(C, packed)]
pub struct TcpHdr {
    pub source:  u16,
    pub dest:    u16,
    pub seq:     u32,
    pub ack_seq: u32,
    pub flags:   u16,  // data_off(4) + reserved(3) + flags(9)
    pub window:  u16,
    pub check:   u16,
    pub urg_ptr: u16,
}

#[repr(C, packed)]
pub struct UdpHdr {
    pub source: u16,
    pub dest:   u16,
    pub len:    u16,
    pub check:  u16,
}

// ─── Parsed Packet Info (lives on stack, < 64 bytes) ──────────────────────────
#[derive(Default)]
pub struct PacketInfo {
    pub src_ip:    u32,   // network byte order
    pub dst_ip:    u32,
    pub src_port:  u16,   // host byte order
    pub dst_port:  u16,
    pub protocol:  u8,
    pub tcp_flags: u8,
    pub pkt_len:   u32,
    pub is_ipv6:   bool,
    pub src_ip6:   [u8; 16],
    pub dst_ip6:   [u8; 16],
    /// Byte offset where the transport-layer payload starts
    pub payload_offset: u32,
}

// ─── Bounds-Check Helper ──────────────────────────────────────────────────────
// MUST be called before EVERY pointer dereference in BPF programs.
// Returns a raw const pointer only if [start, start+size) lies within the packet.
// The verifier tracks these checks and verifies them statically.
#[inline(always)]
pub unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end   = ctx.data_end();
    let len   = mem::size_of::<T>();

    // Verifier requires explicit arithmetic to prove non-overflow
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

// ─── Main Packet Parser ───────────────────────────────────────────────────────
/// Parses the packet headers and fills PacketInfo.
/// Returns Err(()) on any malformed/truncated packet.
/// Called inline from the XDP main function — no BPF-to-BPF call overhead.
#[inline(always)]
pub fn parse_packet(ctx: &XdpContext) -> Result<PacketInfo, ()> {
    let mut info = PacketInfo::default();
    info.pkt_len = (ctx.data_end() - ctx.data()) as u32;

    // ── Layer 2: Ethernet ─────────────────────────────────────────────────────
    let eth: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let ether_type = u16::from_be(unsafe { (*eth).ether_type });

    let mut offset = mem::size_of::<EthHdr>();  // 14 bytes

    match ether_type {
        // ── Layer 3: IPv4 ─────────────────────────────────────────────────────
        x if x == ethertype::IPV4 => {
            let ip: *const Ipv4Hdr = unsafe { ptr_at(ctx, offset)? };

            // IHL field encodes header length in 32-bit words (min 5 = 20 bytes)
            let ihl = unsafe { ((*ip).version_ihl & 0x0F) as usize };
            if ihl < 5 {
                return Err(());  // Reject: malformed IHL
            }
            let ip_hdr_len = ihl * 4;

            info.src_ip   = unsafe { (*ip).src_addr };  // Already network order
            info.dst_ip   = unsafe { (*ip).dst_addr };
            info.protocol = unsafe { (*ip).protocol };

            offset += ip_hdr_len;

            // ── Layer 4: TCP ──────────────────────────────────────────────────
            if info.protocol == proto::TCP {
                let tcp: *const TcpHdr = unsafe { ptr_at(ctx, offset)? };
                info.src_port  = u16::from_be(unsafe { (*tcp).source });
                info.dst_port  = u16::from_be(unsafe { (*tcp).dest });
                // TCP flags are the low 9 bits of the flags field
                info.tcp_flags = (u16::from_be(unsafe { (*tcp).flags }) & 0x1FF) as u8;

                // Data offset field (high 4 bits) = TCP header length in 32-bit words
                let data_off = (u16::from_be(unsafe { (*tcp).flags }) >> 12) as usize;
                if data_off < 5 { return Err(()); }
                offset += data_off * 4;
            }
            // ── Layer 4: UDP ──────────────────────────────────────────────────
            else if info.protocol == proto::UDP {
                let udp: *const UdpHdr = unsafe { ptr_at(ctx, offset)? };
                info.src_port = u16::from_be(unsafe { (*udp).source });
                info.dst_port = u16::from_be(unsafe { (*udp).dest });
                offset += mem::size_of::<UdpHdr>();
            }
            // ICMP and others: no port info, continue with IP-level only
        }

        // ── Layer 3: IPv6 ─────────────────────────────────────────────────────
        x if x == ethertype::IPV6 => {
            let ip6: *const Ipv6Hdr = unsafe { ptr_at(ctx, offset)? };

            info.src_ip6  = unsafe { (*ip6).src_addr };
            info.dst_ip6  = unsafe { (*ip6).dst_addr };
            info.protocol = unsafe { (*ip6).next_hdr };
            info.is_ipv6  = true;

            offset += mem::size_of::<Ipv6Hdr>();  // 40 bytes (fixed IPv6 header)

            // Phase 2: handle only fixed IPv6 header (no extension headers).
            // Extension header chasing added in Phase 3.
            if info.protocol == proto::TCP {
                let tcp: *const TcpHdr = unsafe { ptr_at(ctx, offset)? };
                info.src_port  = u16::from_be(unsafe { (*tcp).source });
                info.dst_port  = u16::from_be(unsafe { (*tcp).dest });
                info.tcp_flags = (u16::from_be(unsafe { (*tcp).flags }) & 0x1FF) as u8;
            } else if info.protocol == proto::UDP {
                let udp: *const UdpHdr = unsafe { ptr_at(ctx, offset)? };
                info.src_port = u16::from_be(unsafe { (*udp).source });
                info.dst_port = u16::from_be(unsafe { (*udp).dest });
            }
        }

        // ARP and other non-IP: pass through silently
        _ => {
            return Ok(PacketInfo {
                pkt_len: info.pkt_len,
                ..Default::default()
            });
        }
    }

    info.payload_offset = offset as u32;
    Ok(info)
}

// ─── TCP Flag Helpers ─────────────────────────────────────────────────────────
pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;

    #[inline(always)]
    pub fn is_syn_only(flags: u8) -> bool {
        flags == SYN
    }

    #[inline(always)]
    pub fn is_syn_ack(flags: u8) -> bool {
        (flags & (SYN | ACK)) == (SYN | ACK)
    }
}

// ─── Mutable Pointer Accessor (for in-place packet rewriting) ─────────────────
// Required by honeypot.rs for XDP_TX header rewriting.
// Identical bounds-check logic to ptr_at() but returns *mut T.
// The BPF verifier tracks mutability; this is ONLY used on packets that
// are about to be XDP_TX'd (never on packets passed to the network stack).
#[inline(always)]
pub unsafe fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end   = ctx.data_end();
    let len   = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *mut T)
}

// ─── IP Helper: Convert network-order u32 to host-order ──────────────────────
#[inline(always)]
pub fn ntohl(x: u32) -> u32 {
    u32::from_be(x)
}

#[inline(always)]
pub fn htonl(x: u32) -> u32 {
    x.to_be()
}
