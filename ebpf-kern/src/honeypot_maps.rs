// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Honeypot BPF maps (ebpf-kern/src/honeypot_maps.rs).
//              Declares maps used exclusively by the silent redirect pipeline.
//              Written by the Go control plane, read by the XDP program at
//              wire speed to rewrite packet destinations.
//
//              Map layout:
//                HONEYPOT_TARGETS: Array of HoneypotTarget (index = target slot)
//                HONEYPOT_ACTIVE:  Array<u32>[1] = currently active target index
//
//              The control plane rotates honeypot targets by updating
//              HONEYPOT_ACTIVE. XDP picks the active target on each redirect.
// =============================================================================

use aya_ebpf::macros::map;
use aya_ebpf::maps::Array;
use crate::honeypot::HoneypotTarget;

/// Maximum number of registered honeypot targets (can be rotated by CP)
pub const MAX_HONEYPOT_TARGETS: u32 = 16;

/// Pool of honeypot destination descriptors.
/// Key: u32 index (0..MAX_HONEYPOT_TARGETS-1)
/// Value: HoneypotTarget (dst IP + dst MAC + port override)
#[map(name = "HONEYPOT_TARGETS")]
pub static mut HONEYPOT_TARGETS: Array<HoneypotTarget> =
    Array::with_max_entries(MAX_HONEYPOT_TARGETS, 0);

/// Single-element array holding the currently active target index.
/// Control plane writes this to rotate between honeypots.
#[map(name = "HONEYPOT_ACTIVE")]
pub static mut HONEYPOT_ACTIVE: Array<u32> =
    Array::with_max_entries(1, 0);
