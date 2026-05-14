// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Go mirror of BPF kernel types (control-plane/internal/bpfmaps/types.go).
//              These structs MUST be byte-for-byte identical to:
//                - ebpf-kern/src/types.rs  (kernel BPF program)
//                - ebpf-user/src/types.rs  (Rust user-space loader)
//
//              Verified by: scripts/verify_abi.sh (runs compile-time size checks).
//              DO NOT change field order or sizes without updating all three files.
//
//              Layout (all little-endian, matching x86-64 BPF):
//                BlockEntry    = 16 bytes
//                RateBucket    = 40 bytes
//                XdpStats      = 80 bytes
//                FailsafeState = 56 bytes
//                FalxMapConfig = 32 bytes
// =============================================================================

package bpfmaps

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"
)

// ─── BlockEntry ───────────────────────────────────────────────────────────────
// Stored in BLOCKLIST_V4 and BLOCKLIST_V6 maps.
// Key: uint32 (IPv4) or [16]byte (IPv6) — source IP, network byte order.
type BlockEntry struct {
	ExpireAt    uint64 // Unix timestamp seconds; 0 = permanent
	Action      uint8  // action.DROP=2, action.REDIRECT=3
	RuleID      uint8  // 0=manual, 1-255=AI rule
	ThreatScore uint8  // 0-100 confidence from AI
	Pad         uint8
	Reason      uint32 // reason code for telemetry
}

// ─── RateBucket ───────────────────────────────────────────────────────────────
// Stored in RATE_LIMIT map. Key: uint32 (source IPv4).
type RateBucket struct {
	Tokens     uint64 // Current available tokens
	LastRefill uint64 // Nanoseconds since boot (bpf_ktime_get_ns)
	Capacity   uint64 // Max tokens (burst size)
	RefillRate uint64 // Nanoseconds per token
	DropCount  uint64 // Cumulative drops from this source
}

// ─── XdpStats ─────────────────────────────────────────────────────────────────
// Stored in XDP_STATS PerCpuArray at index 0.
// Aggregated across all CPUs by the control plane.
type XdpStats struct {
	RxPackets     uint64
	RxBytes       uint64
	Dropped       uint64
	RateLimited   uint64
	Passed        uint64
	Redirected    uint64
	FailsafeDrops uint64
	ParseErrors   uint64
	MapErrors     uint64
	LastResetNs   uint64
}

// Add implements aggregation across CPUs (saturating arithmetic)
func (a XdpStats) Add(b XdpStats) XdpStats {
	return XdpStats{
		RxPackets:     safeAdd(a.RxPackets, b.RxPackets),
		RxBytes:       safeAdd(a.RxBytes, b.RxBytes),
		Dropped:       safeAdd(a.Dropped, b.Dropped),
		RateLimited:   safeAdd(a.RateLimited, b.RateLimited),
		Passed:        safeAdd(a.Passed, b.Passed),
		Redirected:    safeAdd(a.Redirected, b.Redirected),
		FailsafeDrops: safeAdd(a.FailsafeDrops, b.FailsafeDrops),
		ParseErrors:   safeAdd(a.ParseErrors, b.ParseErrors),
		MapErrors:     safeAdd(a.MapErrors, b.MapErrors),
		LastResetNs:   maxU64(a.LastResetNs, b.LastResetNs),
	}
}

// ─── FailsafeState ────────────────────────────────────────────────────────────
// Stored in FAILSAFE_STATE Array at index 0.
// CRITICAL: Pad field must be [7]byte to match Rust repr(C) layout.
type FailsafeState struct {
	CircuitOpen   uint8
	Pad           [7]byte // Must be exactly 7 bytes — matches Rust _pad: [u8; 7]
	CurrentPPS    uint64
	CurrentBPS    uint64
	OpenSinceNs   uint64
	PPSThreshold  uint64
	BPSThreshold  uint64
	WindowStartNs uint64
}

// ─── FalxMapConfig ────────────────────────────────────────────────────────────
// Stored in CONFIG Array at index 0.
// Written by control plane to push policy changes without BPF reload.
type FalxMapConfig struct {
	DefaultAction    uint8
	RateLimitEnabled uint8
	FailsafeEnabled  uint8
	AFXDPRedirect    uint8
	Pad              [4]byte
	RateCapacity     uint64
	RateRefillNs     uint64
	HoneypotIP       uint32
	HoneypotPort     uint16
	Pad2             [2]byte
}

// ─── Action Constants ─────────────────────────────────────────────────────────
const (
	ActionPass      uint8 = 1
	ActionDrop      uint8 = 2
	ActionRedirect  uint8 = 3
	ActionRateLimit uint8 = 4
)

// ─── Reason Codes ─────────────────────────────────────────────────────────────
const (
	ReasonBlocklist  uint32 = 0x0001
	ReasonRateLimit  uint32 = 0x0002
	ReasonFailsafe   uint32 = 0x0003
	ReasonParseErr   uint32 = 0x0004
	ReasonAIVerdict  uint32 = 0x0005
)

// ─── Map Index Constants ──────────────────────────────────────────────────────
const (
	StatsIdx    uint32 = 0
	FailsafeIdx uint32 = 0
	ConfigIdx   uint32 = 0
)

// ─── ABI Size Verification ───────────────────────────────────────────────────
// These are validated at init() and panic on mismatch.
// Run verify_abi.sh to cross-check against Rust structs.
func init() {
	type sizeCheck struct {
		name string
		got  uintptr
		want uintptr
	}
	checks := []sizeCheck{
		{"BlockEntry",    unsafe.Sizeof(BlockEntry{}),    16},
		{"RateBucket",    unsafe.Sizeof(RateBucket{}),    40},
		{"XdpStats",      unsafe.Sizeof(XdpStats{}),      80},
		{"FailsafeState", unsafe.Sizeof(FailsafeState{}), 56},
		{"FalxMapConfig", unsafe.Sizeof(FalxMapConfig{}), 32},
	}
	for _, c := range checks {
		if c.got != c.want {
			panic(fmt.Sprintf(
				"[FALX ABI MISMATCH] %s: Go size=%d, expected=%d. "+
					"Update types.go to match ebpf-kern/src/types.rs",
				c.name, c.got, c.want,
			))
		}
	}
}

// ─── IP Helpers ───────────────────────────────────────────────────────────────

// IPv4ToUint32 converts net.IP to uint32 in network byte order (matches kernel)
func IPv4ToUint32(ip net.IP) (uint32, error) {
	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("not an IPv4 address")
	}
	return binary.BigEndian.Uint32(ip), nil
}

// Uint32ToIPv4 converts a uint32 (network order) back to net.IP
func Uint32ToIPv4(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

// IPv6ToBytes converts net.IP to [16]byte
func IPv6ToBytes(ip net.IP) ([16]byte, error) {
	ip = ip.To16()
	if ip == nil {
		return [16]byte{}, fmt.Errorf("invalid IPv6 address")
	}
	var b [16]byte
	copy(b[:], ip)
	return b, nil
}

// ─── Arithmetic Helpers ───────────────────────────────────────────────────────
func safeAdd(a, b uint64) uint64 {
	if a > ^b {
		return ^uint64(0) // saturate at max
	}
	return a + b
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
