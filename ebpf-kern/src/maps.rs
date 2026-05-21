// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: BPF map declarations (ebpf-kern/src/maps.rs).
//              All maps are pinned to the BPF filesystem at /sys/fs/bpf/falx/
//              and opened by the control plane via file descriptors.
//
//              Map layout MUST stay in sync with control-plane/pkg/bpfmaps/.
//
//              Phase-10 additions:
//                - MAPPED_XDP_STATS : PerCpuArray<MappedXdpStats>
//                  Slim 48-byte per-CPU accumulator (1 cache line).
//
//                - BLOOM_FILTER     : BloomFilter<u32>
//                  Pre-filter ahead of BLOCKLIST_V4. Linux ≥ 5.16.
//
//              Phase-11 additions:
//                - COOLING_TRACKER  : LruHashMap<u32, CoolingEntry>
//                  Exponential-backoff ban escalator (T_ban = 10s × 2^r).
//                  Option B: no bpf_spin_lock — BTF-free, race-tolerant.
//
//              Map Security:
//              - LruHashMap evicts oldest entries — memory-exhaustion DoS proof.
//              - BPF_F_NO_PREALLOC where supported limits kernel memory use.
//              - Map write rate-limiting is enforced at the Go control-plane
//                layer to keep the XDP hot path branch-free.
// =============================================================================

use aya_ebpf::macros::map;
use aya_ebpf::maps::{
    Array,
    BloomFilter,
    LruHashMap,
    PerCpuArray,
};

use crate::types::{
    BlockEntry, CoolingEntry, FalxMapConfig, FailsafeState,
    MappedXdpStats, RateBucket, SynCountEntry, XdpStats,
};

// ─── IPv4 Blocklist ───────────────────────────────────────────────────────────
// Key:   u32        = source IPv4 address (network byte order)
// Value: BlockEntry = action + TTL expiry + AI threat metadata
// LRU:  evicts oldest entry when full (memory-exhaustion DoS proof)
// Size: 65,536 entries ≈ 5 MB footprint
//
// Written by: control plane (manual/AI blocks) + XDP apply_cooling_ban()
// Read by:    XDP check_blocklist_v4() after bloom filter pre-screen
#[map(name = "BLOCKLIST_V4")]
pub static mut BLOCKLIST_V4: LruHashMap<u32, BlockEntry> =
    LruHashMap::with_max_entries(65_536, 0);

// ─── IPv6 Blocklist ───────────────────────────────────────────────────────────
#[map(name = "BLOCKLIST_V6")]
pub static mut BLOCKLIST_V6: LruHashMap<[u8; 16], BlockEntry> =
    LruHashMap::with_max_entries(65_536, 0);

// ─── Bloom Filter Pre-Screener ────────────────────────────────────────────────
// BPF_MAP_TYPE_BLOOM_FILTER — Linux 5.16+. Value type: u32 (src_ip).
//
// False positive rate: ~1.1% at 50% fill with default 3 hash functions.
// FP cost: one unnecessary LRU lookup (not a correctness issue).
//
// Attack mitigation: hping3 --rand-source generates IPs that are never in the
// blocklist. Without the bloom filter, each random IP costs a full LRU hash
// lookup. With the bloom filter, ~98.9% of random IPs are rejected in O(k=3)
// hashes without pointer-chasing into the LRU.
//
// Populated by:
//   - Control plane BlockIPv4() / BlockIPv4Batch() for manual and AI blocks.
//   - XDP apply_cooling_ban() for auto-bans.
#[map(name = "BLOOM_FILTER")]
pub static mut BLOOM_FILTER: BloomFilter<u32> =
    BloomFilter::with_max_entries(65_536, 0);

// ─── Cooling Tracker (Exponential Backoff Ban Escalator) ──────────────────────
// BPF_MAP_TYPE_LRU_HASH — Linux 4.15+.
// Key:   u32          = source IPv4 address (network byte order)
// Value: CoolingEntry = repeat_count (u32) + _pad (u32) + last_ban_at_ns (u64)
//
// Option B — Race-Tolerant Best-Effort:
//   No bpf_spin_lock; no BTF requirement. repeat_count RMW is unprotected.
//   Under concurrent multi-CPU floods the count may under-count, but every
//   code path still issues a correct timed BLOCKLIST_V4 block.
//
// Ban escalation:
//   T_ban_s = 10 << min(repeat_count, 16)   (10 s → 7.5 days)
//
// After computing T_ban, apply_cooling_ban:
//   1. Updates this map entry (best-effort, no lock).
//   2. Inserts a timed block into BLOCKLIST_V4 (expire_at = now_s + T_ban).
//   3. Calls BLOOM_FILTER.insert(&src_ip, 0) so the gate activates immediately.
//
// LRU eviction resets repeat_count to 0 — an intentional amnesty.
#[map(name = "COOLING_TRACKER")]
pub static mut COOLING_TRACKER: LruHashMap<u32, CoolingEntry> =
    LruHashMap::with_max_entries(65_536, 0);

// ─── SYN Flood Counter ────────────────────────────────────────────────────────
// BPF_MAP_TYPE_LRU_HASH — Linux 4.15+.
// Key:   u32           = source IPv4 address (network byte order)
// Value: SynCountEntry = syn_count (u32) + ack_count (u32)
//
// check_syn_counter() increments syn_count on each SYN-only packet and
// resets it to 0 on ACK packets (handshake completions). When syn_count
// reaches SYN_FLOOD_THRESHOLD (50) with ack_count == 0, a max-penalty ban
// (r = SYN_FLOOD_PENALTY_R = 8 → T_ban ≥ 2 560 s) is issued and syn_count
// is reset, so the mechanism re-arms for the next burst.
// LRU eviction provides implicit amnesty for idle sources.
#[map(name = "SYN_COUNTER")]
pub static mut SYN_COUNTER: LruHashMap<u32, SynCountEntry> =
    LruHashMap::with_max_entries(65_536, 0);

// ─── Rate Limit Buckets ───────────────────────────────────────────────────────
#[map(name = "RATE_LIMIT")]
pub static mut RATE_LIMIT: LruHashMap<u32, RateBucket> =
    LruHashMap::with_max_entries(65_536, 0);

// ─── Compact Per-CPU XDP Statistics (MAPPED_XDP_STATS) ───────────────────────
// 48 bytes = 6 × u64 — exactly one 64-byte CPU cache line.
// Zero contention, zero atomic ops, zero cache-line bouncing.
// Index 0 = per-CPU global counters (only slot ever used).
#[map(name = "MAPPED_XDP_STATS")]
pub static mut MAPPED_XDP_STATS: PerCpuArray<MappedXdpStats> =
    PerCpuArray::with_max_entries(1, 0);

// ─── Full Per-CPU XDP Statistics (XDP_STATS) ─────────────────────────────────
// Updated only for extended/cold-path counters: rate_limited, redirected,
// failsafe_drops, parse_errors, map_errors, cooling_bans.
#[map(name = "XDP_STATS")]
pub static mut XDP_STATS: PerCpuArray<XdpStats> =
    PerCpuArray::with_max_entries(1, 0);

// ─── Failsafe / Circuit Breaker State ────────────────────────────────────────
// Shared between XDP (reads thresholds, writes pps/bps counters)
// and control plane (reads counters, writes circuit_open + thresholds).
#[map(name = "FAILSAFE_STATE")]
pub static mut FAILSAFE_STATE: Array<FailsafeState> =
    Array::with_max_entries(1, 0);

// ─── Runtime Configuration ────────────────────────────────────────────────────
// Written by control plane to push policy changes without BPF reload.
// 32 bytes — fits in half a cache line.
#[map(name = "CONFIG")]
pub static mut CONFIG: Array<FalxMapConfig> =
    Array::with_max_entries(1, 0);

// ─── AF_XDP Redirect Map ──────────────────────────────────────────────────────
#[map(name = "XSK_MAP")]
pub static mut XSK_MAP: aya_ebpf::maps::XskMap =
    aya_ebpf::maps::XskMap::with_max_entries(1, 0);
