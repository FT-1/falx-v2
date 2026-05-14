// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: Packet metadata (control-plane/internal/afxdp/packet.go).
//              After the AF_XDP bridge receives a packet from the RX ring,
//              it parses the raw frame bytes and produces a PacketMeta struct.
//              This struct is the payload sent to the AI inference engine.
//
//              Parsing mirrors the BPF kernel parser (ebpf-kern/src/parser.rs)
//              but runs in user-space with full standard library support.
//
//              Memory contract:
//                frame bytes → parse → PacketMeta → AI engine channel
//                After parse: frame is returned to FILL ring (zero-copy)
//                PacketMeta is heap-allocated (one alloc per packet batch)
// =============================================================================

package afxdp

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ─── Protocol Constants ───────────────────────────────────────────────────────
const (
	EthTypeIPv4 = 0x0800
	EthTypeIPv6 = 0x86DD
	EthTypeARP  = 0x0806

	ProtoICMP   = 1
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58

	EthHdrLen  = 14
	IPv4HdrMin = 20
	IPv6HdrLen = 40
	TCPHdrMin  = 20
	UDPHdrLen  = 8
)

// ─── PacketMeta ───────────────────────────────────────────────────────────────
// Parsed packet metadata. Matches the proto definition in ipc/proto/falx.proto.
// Sent to AI inference engine via gRPC (Phase 9).
type PacketMeta struct {
	// Layer 3
	SrcIP    net.IP
	DstIP    net.IP
	IsIPv6   bool

	// Layer 4
	Protocol uint8
	SrcPort  uint16
	DstPort  uint16
	TCPFlags uint16

	// Metrics
	PktLen uint32
	FlowID uint64 // 5-tuple hash (computed here, matches BPF flow_id)

	// Payload sample (first 64 bytes of L4 payload for AI features)
	PayloadSample []byte

	// UMEM frame descriptor — used to return the frame after processing
	UMEMOffset uint64
}

// ─── Parser ───────────────────────────────────────────────────────────────────
// ParseFrame extracts packet metadata from a raw UMEM frame byte slice.
// Returns an error for malformed or unsupported packets.
func ParseFrame(frame []byte, umemOffset uint64) (*PacketMeta, error) {
	if len(frame) < EthHdrLen {
		return nil, fmt.Errorf("frame too short: %d bytes", len(frame))
	}

	meta := &PacketMeta{
		PktLen:     uint32(len(frame)),
		UMEMOffset: umemOffset,
	}

	// ── Ethernet ────────────────────────────────────────────────────────────
	etherType := binary.BigEndian.Uint16(frame[12:14])
	offset    := EthHdrLen

	switch etherType {
	// ── IPv4 ────────────────────────────────────────────────────────────────
	case EthTypeIPv4:
		if len(frame) < offset+IPv4HdrMin {
			return nil, fmt.Errorf("truncated IPv4 header")
		}
		ihl := int(frame[offset]&0x0F) * 4
		if ihl < IPv4HdrMin || offset+ihl > len(frame) {
			return nil, fmt.Errorf("invalid IHL: %d", ihl)
		}

		meta.SrcIP    = net.IP(frame[offset+12 : offset+16]).To4()
		meta.DstIP    = net.IP(frame[offset+16 : offset+20]).To4()
		meta.Protocol = frame[offset+9]
		meta.IsIPv6   = false
		offset       += ihl

		if err := parseL4(frame, offset, meta); err != nil {
			return meta, nil // L4 parse failure is non-fatal for IP-level decisions
		}

	// ── IPv6 ────────────────────────────────────────────────────────────────
	case EthTypeIPv6:
		if len(frame) < offset+IPv6HdrLen {
			return nil, fmt.Errorf("truncated IPv6 header")
		}

		meta.SrcIP    = net.IP(frame[offset+8 : offset+24]).To16()
		meta.DstIP    = net.IP(frame[offset+24 : offset+40]).To16()
		meta.Protocol = frame[offset+6] // next header
		meta.IsIPv6   = true
		offset       += IPv6HdrLen

		if err := parseL4(frame, offset, meta); err != nil {
			return meta, nil
		}

	default:
		// ARP and others: return IP-less meta for stats purposes
		return meta, nil
	}

	// ── Flow ID (5-tuple hash) ────────────────────────────────────────────
	meta.FlowID = computeFlowID(meta)

	return meta, nil
}

// parseL4 parses TCP/UDP headers and extracts port numbers and flags.
func parseL4(frame []byte, offset int, meta *PacketMeta) error {
	remaining := len(frame) - offset

	switch meta.Protocol {
	case ProtoTCP:
		if remaining < TCPHdrMin {
			return fmt.Errorf("truncated TCP header")
		}
		meta.SrcPort  = binary.BigEndian.Uint16(frame[offset : offset+2])
		meta.DstPort  = binary.BigEndian.Uint16(frame[offset+2 : offset+4])
		meta.TCPFlags = binary.BigEndian.Uint16(frame[offset+12 : offset+14]) & 0x01FF
		dataOffset   := int((frame[offset+12] >> 4) * 4)
		payloadStart := offset + dataOffset
		if payloadStart < len(frame) {
			end := payloadStart + 64
			if end > len(frame) {
				end = len(frame)
			}
			meta.PayloadSample = make([]byte, end-payloadStart)
			copy(meta.PayloadSample, frame[payloadStart:end])
		}

	case ProtoUDP:
		if remaining < UDPHdrLen {
			return fmt.Errorf("truncated UDP header")
		}
		meta.SrcPort = binary.BigEndian.Uint16(frame[offset : offset+2])
		meta.DstPort = binary.BigEndian.Uint16(frame[offset+2 : offset+4])
		payloadStart := offset + UDPHdrLen
		if payloadStart < len(frame) {
			end := payloadStart + 64
			if end > len(frame) {
				end = len(frame)
			}
			meta.PayloadSample = make([]byte, end-payloadStart)
			copy(meta.PayloadSample, frame[payloadStart:end])
		}
	}
	return nil
}

// ─── Flow ID Hash (FNV-1a, matches BPF 5-tuple hash) ─────────────────────────
// Produces a deterministic 64-bit hash of the 5-tuple.
// The same hash is computed in XDP (Phase 2 / ebpf-kern), allowing the
// AI engine to correlate kernel-level flow IDs with user-space decisions.
func computeFlowID(m *PacketMeta) uint64 {
	const (
		fnvOffset64 = 14695981039346656037
		fnvPrime64  = 1099511628211
	)

	h := uint64(fnvOffset64)

	fnv := func(b []byte) {
		for _, c := range b {
			h ^= uint64(c)
			h *= fnvPrime64
		}
	}

	if m.SrcIP != nil {
		fnv(m.SrcIP)
	}
	if m.DstIP != nil {
		fnv(m.DstIP)
	}

	var ports [4]byte
	binary.BigEndian.PutUint16(ports[0:2], m.SrcPort)
	binary.BigEndian.PutUint16(ports[2:4], m.DstPort)
	fnv(ports[:])
	fnv([]byte{m.Protocol})

	return h
}

// ─── TCP Flag Helpers ─────────────────────────────────────────────────────────
func IsSYNOnly(flags uint16)  bool { return flags == 0x002 }
func IsACK(flags uint16)      bool { return flags&0x010 != 0 }
func IsRST(flags uint16)      bool { return flags&0x004 != 0 }
func IsFIN(flags uint16)      bool { return flags&0x001 != 0 }
