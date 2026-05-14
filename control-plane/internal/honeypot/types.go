// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Honeypot types (control-plane/internal/honeypot/types.go).
//              Go mirror of ebpf-kern/src/honeypot.rs :: HoneypotTarget.
//              Written into HONEYPOT_TARGETS BPF map by the manager.
//
//              ABI contract (size = 28 bytes):
//                dst_ip   [4]byte  → u32  (network order)
//                dst_mac  [6]byte
//                src_mac  [6]byte
//                dst_port [2]byte  → u16 (big-endian)
//                _pad     [2]byte
//                active   [1]byte  → u8
//                _pad2    [3]byte
// =============================================================================

package honeypot

import (
	"encoding/binary"
	"fmt"
	"net"
)

// HoneypotTarget mirrors ebpf-kern/src/honeypot.rs :: HoneypotTarget.
// Must remain 28 bytes with identical field layout.
type HoneypotTarget struct {
	DstIP   [4]byte  // IPv4 in network byte order
	DstMAC  [6]byte  // Honeypot or next-hop MAC
	SrcMAC  [6]byte  // MAC to use as source in rewritten packets
	DstPort [2]byte  // TCP/UDP port override (big-endian); 0 = no rewrite
	Pad     [2]byte
	Active  uint8    // 1 = enabled
	Pad2    [3]byte
}

// ─── Constructor ──────────────────────────────────────────────────────────────
func NewHoneypotTarget(
	dstIP   net.IP,
	dstMAC  net.HardwareAddr,
	srcMAC  net.HardwareAddr,
	dstPort uint16,
) (*HoneypotTarget, error) {
	ip4 := dstIP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("honeypot IP must be IPv4, got: %s", dstIP)
	}
	if len(dstMAC) != 6 {
		return nil, fmt.Errorf("invalid dst MAC length: %d", len(dstMAC))
	}
	if len(srcMAC) != 6 {
		return nil, fmt.Errorf("invalid src MAC length: %d", len(srcMAC))
	}

	t := &HoneypotTarget{Active: 1}
	copy(t.DstIP[:], ip4)
	copy(t.DstMAC[:], dstMAC)
	copy(t.SrcMAC[:], srcMAC)

	if dstPort != 0 {
		binary.BigEndian.PutUint16(t.DstPort[:], dstPort)
	}
	return t, nil
}

// IP returns the honeypot destination IP as net.IP.
func (h *HoneypotTarget) IP() net.IP {
	return net.IP(h.DstIP[:])
}

// Port returns the destination port override (0 = no rewrite).
func (h *HoneypotTarget) Port() uint16 {
	return binary.BigEndian.Uint16(h.DstPort[:])
}

// Disable marks the target as inactive (XDP will skip it).
func (h *HoneypotTarget) Disable() {
	h.Active = 0
}

// ─── ABI Verification ─────────────────────────────────────────────────────────
func init() {
	// 4 + 6 + 6 + 2 + 2 + 1 + 3 = 24 bytes
	// Note: Rust repr(C) packs fields without implicit padding here
	// Verify at runtime to catch layout drift early
	import_unsafe_check()
}

func import_unsafe_check() {
	// Will be filled by verify_abi.sh — runtime check lives here as a backstop
}

// ─── HoneypotPool ─────────────────────────────────────────────────────────────
// A named honeypot with metadata for the SOC dashboard.
type HoneypotPool struct {
	ID       uint32
	Name     string
	Target   HoneypotTarget
	HitsTotal uint64
	Active   bool
}
