// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: BPF map declarations (ebpf-kern/src/maps.rs).
//              All maps are declared with static lifetime (pinned to BPF FS).
//              The control plane reads/writes these maps via file descriptors.
//              Map layout MUST stay in sync with control-plane/internal/bpfmaps/.
//
//              Map Security (Phase 3 detail):
//              - All maps use BPF_F_NO_PREALLOC where supported to limit
//                memory exhaustion.
//              - LruHashMap evicts oldest entries automatically — prevents
//                the blocklist from being used as a memory DoS vector.
//              - Map write rate-limiting is enforced at the control-plane
//                layer (Go), not inside the kernel program, to keep the
//                XDP hot path branch-free.
// =============================================================================

use aya_ebpf::macros::map;
use aya_ebpf::maps::{
    LruHashMap,
    PerCpuArray,
    Array,
    HashMap,
};

use crate::types::{BlockEntry, RateBucket, XdpStats, FailsafeState, FalxMapConfig};

// ─── IPv4 Blocklist ───────────────────────────────────────────────────────────
// Key:   u32   = source IPv4 address (network byte order)
// Value: BlockEntry = action + expiry + metadata
// Type: LRU — evicts oldest entry when full (prevents memory exhaustion DoS)
// Max: 65536 entries (~5 MB footprint)
#[map(name = "BLOCKLIST_V4")]
pub static mut BLOCKLIST_V4: LruHashMap<u32, BlockEntry> =
    LruHashMap::with_max_entries(65536, 0);

// ─── IPv6 Blocklist ───────────────────────────────────────────────────────────
// Key:   [u8; 16] = source IPv6 address (network byte order)
// Value: BlockEntry
#[map(name = "BLOCKLIST_V6")]
pub static mut BLOCKLIST_V6: LruHashMap<[u8; 16], BlockEntry> =
    LruHashMap::with_max_entries(65536, 0);

// ─── Rate Limit Buckets ───────────────────────────────────────────────────────
// Key:   u32 = source IPv4 (one bucket per source)
// Value: RateBucket = token bucket state
// LRU eviction prevents memory exhaustion from distributed sources
#[map(name = "RATE_LIMIT")]
pub static mut RATE_LIMIT: LruHashMap<u32, RateBucket> =
    LruHashMap::with_max_entries(65536, 0);

// ─── Per-CPU XDP Statistics ───────────────────────────────────────────────────
// PerCpuArray ensures each CPU core writes to its own slot — zero contention,
// zero atomic operations, zero cache line bouncing.
// The control plane aggregates across CPUs when it reads stats.
// Index 0: global counters
#[map(name = "XDP_STATS")]
pub static mut XDP_STATS: PerCpuArray<XdpStats> =
    PerCpuArray::with_max_entries(1, 0);

// ─── Failsafe / Circuit Breaker State ────────────────────────────────────────
// Shared between XDP (reads thresholds, writes current_pps/bps)
// and control plane (reads counters, writes circuit_open flag).
// Array type chosen for O(1) lookup by constant index.
#[map(name = "FAILSAFE_STATE")]
pub static mut FAILSAFE_STATE: Array<FailsafeState> =
    Array::with_max_entries(1, 0);

// ─── Runtime Configuration ────────────────────────────────────────────────────
// Written by control plane to push policy changes.
// XDP reads on every packet — kept tiny to stay in L1 cache.
#[map(name = "CONFIG")]
pub static mut CONFIG: Array<FalxMapConfig> =
    Array::with_max_entries(1, 0);

// ─── AF_XDP Redirect Map (Phase 4) ───────────────────────────────────────────
// XSK (AF_XDP socket) redirect map. Key = queue_id, Value = xsk_fd.
// Declared here so the map exists from Phase 2 onward;
// populated by the user-space loader in Phase 4.
#[map(name = "XSK_MAP")]
pub static mut XSK_MAP: aya_ebpf::maps::XskMap =
    aya_ebpf::maps::XskMap::with_max_entries(1, 0);
