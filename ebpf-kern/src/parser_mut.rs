// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Mutable pointer helper for in-place packet header rewriting.
//              Added to support Phase 6 honeypot redirect (honeypot.rs).
//              Identical bounds-check logic to ptr_at() but returns *mut T.
//
// NOTE: ptr_at_mut<T> has been merged into parser.rs (Phase 6 integration).
//       This file is retained for historical reference only and is NOT
//       compiled into the BPF object. Do not re-add the function here.
//       See: ebpf-kern/src/parser.rs :: ptr_at_mut
// =============================================================================
