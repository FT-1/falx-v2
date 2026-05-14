// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Mutable pointer helper for in-place packet header rewriting.
//              Added to support Phase 6 honeypot redirect (honeypot.rs).
//              Identical bounds-check logic to ptr_at() but returns *mut T.
// =============================================================================

// ─── Append to ebpf-kern/src/parser.rs ───────────────────────────────────────
// This file is a patch/addendum — its contents are to be merged into
// parser.rs. Kept separate for clarity in Phase 6 review.

use aya_ebpf::programs::XdpContext;
use core::mem;

/// Mutable variant of ptr_at<T>. Required for in-place header rewriting.
/// The BPF verifier tracks mutability; this function is ONLY called on
/// packets that are about to be XDP_TX'd (not passed to the stack).
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
