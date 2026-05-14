// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: IPC wire protocol (control-plane/internal/ipc/protocol.go).
//              Defines the binary framing protocol used between the control
//              plane (Go) and the AI inference engine (C++/Python) over
//              Unix domain sockets + shared memory.
//
//              Frame layout (little-endian):
//                ┌─────────────────────────────────────────────────────────┐
//                │ Magic   [4]byte  = 0x46 0x4C 0x58 0x32  ("FLX2")       │
//                │ Version uint8   = 1                                     │
//                │ Type    uint8   = MsgType                               │
//                │ Flags   uint16  = flag bits                             │
//                │ Seq     uint32  = sequence number (for request-reply)   │
//                │ Len     uint32  = payload length in bytes               │
//                │ CRC32   uint32  = CRC32 of (header[0:12] + payload)    │
//                ├─────────────────────────────────────────────────────────┤
//                │ Payload [Len]byte                                       │
//                └─────────────────────────────────────────────────────────┘
//              Header = 20 bytes fixed. Max payload = 1 MiB.
//
//              This layout is implemented identically in:
//                - control-plane/internal/ipc/protocol.go (Go — this file)
//                - ai-inference/src/ipc_protocol.hpp      (C++)
//                - ai-inference/ipc_protocol.py           (Python stub)
// =============================================================================

package ipc

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

// ─── Constants ────────────────────────────────────────────────────────────────
var MagicBytes = [4]byte{0x46, 0x4C, 0x58, 0x32} // "FLX2"

const (
	ProtocolVersion = uint8(1)
	HeaderSize      = 20   // bytes
	MaxPayloadSize  = 1 << 20 // 1 MiB
)

// ─── Message Types ────────────────────────────────────────────────────────────
type MsgType uint8

const (
	// Control plane → AI engine
	MsgTypeInferRequest  MsgType = 0x01 // Batch of PacketMeta for analysis
	MsgTypeConfigPush    MsgType = 0x02 // Push new inference config
	MsgTypeHeartbeat     MsgType = 0x03 // Keepalive ping

	// AI engine → Control plane
	MsgTypeInferResponse MsgType = 0x81 // Batch of Verdicts
	MsgTypeMapUpdateReq  MsgType = 0x82 // Request to update BPF map
	MsgTypeHeartbeatAck  MsgType = 0x83 // Keepalive pong
	MsgTypeAlert         MsgType = 0x84 // Threat alert (no block action needed)
	MsgTypeMapUpdateAck  MsgType = 0x85 // ACK that a map update was applied

	// Bidirectional
	MsgTypeError         MsgType = 0xFF // Error response
)

func (m MsgType) String() string {
	switch m {
	case MsgTypeInferRequest:   return "InferRequest"
	case MsgTypeConfigPush:     return "ConfigPush"
	case MsgTypeHeartbeat:      return "Heartbeat"
	case MsgTypeInferResponse:  return "InferResponse"
	case MsgTypeMapUpdateReq:   return "MapUpdateReq"
	case MsgTypeHeartbeatAck:   return "HeartbeatAck"
	case MsgTypeMapUpdateAck:   return "MapUpdateAck"
	case MsgTypeAlert:          return "Alert"
	case MsgTypeError:          return "Error"
	default:                    return fmt.Sprintf("Unknown(0x%02x)", uint8(m))
	}
}

// ─── Flags ────────────────────────────────────────────────────────────────────
const (
	FlagCompressed uint16 = 1 << 0 // Payload is zstd-compressed
	FlagEncrypted  uint16 = 1 << 1 // Payload is encrypted (Phase 8+ option)
	FlagAckRequired uint16= 1 << 2 // Sender expects a response with same Seq
)

// ─── Frame Header ─────────────────────────────────────────────────────────────
// Fixed-size 20-byte header. All fields little-endian.
type FrameHeader struct {
	Magic   [4]byte
	Version uint8
	Type    MsgType
	Flags   uint16
	Seq     uint32
	Len     uint32
	CRC32   uint32
}

// ─── Serialisation ────────────────────────────────────────────────────────────
func (h *FrameHeader) Marshal() [HeaderSize]byte {
	var b [HeaderSize]byte
	copy(b[0:4], h.Magic[:])
	b[4] = h.Version
	b[5] = uint8(h.Type)
	binary.LittleEndian.PutUint16(b[6:8],   h.Flags)
	binary.LittleEndian.PutUint32(b[8:12],  h.Seq)
	binary.LittleEndian.PutUint32(b[12:16], h.Len)
	binary.LittleEndian.PutUint32(b[16:20], h.CRC32)
	return b
}

func UnmarshalHeader(b [HeaderSize]byte) (FrameHeader, error) {
	h := FrameHeader{}
	copy(h.Magic[:], b[0:4])
	if h.Magic != MagicBytes {
		return h, fmt.Errorf("invalid magic: got %x, want %x", h.Magic, MagicBytes)
	}
	h.Version = b[4]
	if h.Version != ProtocolVersion {
		return h, fmt.Errorf("unsupported protocol version %d", h.Version)
	}
	h.Type  = MsgType(b[5])
	h.Flags = binary.LittleEndian.Uint16(b[6:8])
	h.Seq   = binary.LittleEndian.Uint32(b[8:12])
	h.Len   = binary.LittleEndian.Uint32(b[12:16])
	h.CRC32 = binary.LittleEndian.Uint32(b[16:20])

	if h.Len > MaxPayloadSize {
		return h, fmt.Errorf("payload length %d exceeds max %d", h.Len, MaxPayloadSize)
	}
	return h, nil
}

// ─── Frame (header + payload) ─────────────────────────────────────────────────
type Frame struct {
	Header  FrameHeader
	Payload []byte
}

// BuildFrame constructs a Frame and computes its CRC32.
func BuildFrame(msgType MsgType, seq uint32, flags uint16, payload []byte) *Frame {
	h := FrameHeader{
		Magic:   MagicBytes,
		Version: ProtocolVersion,
		Type:    msgType,
		Flags:   flags,
		Seq:     seq,
		Len:     uint32(len(payload)),
	}
	// CRC32 covers header bytes [0:16] + payload
	hBytes := h.Marshal()
	crc := crc32.NewIEEE()
	crc.Write(hBytes[:16])
	crc.Write(payload)
	h.CRC32 = crc.Sum32()

	return &Frame{Header: h, Payload: payload}
}

// Validate checks the CRC32 of a received frame.
func (f *Frame) Validate() error {
	hBytes := f.Header.Marshal()
	crc := crc32.NewIEEE()
	crc.Write(hBytes[:16])
	crc.Write(f.Payload)
	if crc.Sum32() != f.Header.CRC32 {
		return fmt.Errorf("CRC32 mismatch: got 0x%08x, expected 0x%08x",
			crc.Sum32(), f.Header.CRC32)
	}
	return nil
}

// ─── Payload Types (JSON-serialised over binary frame) ────────────────────────

// InferRequest: control plane → AI engine
type InferRequest struct {
	RequestID uint64       `json:"request_id"`
	Packets   []PacketMeta `json:"packets"`
}

// PacketMeta: mirror of afxdp.PacketMeta for IPC serialisation
type PacketMeta struct {
	SrcIP         string `json:"src_ip"`
	DstIP         string `json:"dst_ip"`
	Protocol      uint8  `json:"protocol"`
	SrcPort       uint16 `json:"src_port"`
	DstPort       uint16 `json:"dst_port"`
	TCPFlags      uint16 `json:"tcp_flags"`
	PktLen        uint32 `json:"pkt_len"`
	FlowID        uint64 `json:"flow_id"`
	IsIPv6        bool   `json:"is_ipv6"`
	PayloadSample []byte `json:"payload_sample,omitempty"`
}

// InferResponse: AI engine → control plane
type InferResponse struct {
	RequestID uint64    `json:"request_id"`
	Verdicts  []Verdict `json:"verdicts"`
}

// Verdict: per-flow decision from AI engine
type Verdict struct {
	FlowID          uint64  `json:"flow_id"`
	SrcIP           string  `json:"src_ip"`
	Action          uint8   `json:"action"`    // bpfmaps.ActionDrop etc.
	Confidence      float64 `json:"confidence"`
	RuleID          uint8   `json:"rule_id"`
	ThreatScore     uint8   `json:"threat_score"`
	BlockDurationS  uint64  `json:"block_duration_s"` // 0 = permanent
	Reason          string  `json:"reason"`
}

// MapUpdateReq: AI engine → control plane (direct map update request)
type MapUpdateReq struct {
	SrcIP          string  `json:"src_ip"`
	Action         uint8   `json:"action"`
	TTLSeconds     uint64  `json:"ttl_s"`
	ThreatScore    uint8   `json:"threat_score"`
	RuleID         uint8   `json:"rule_id"`
	Reason         string  `json:"reason"`
	Actor          string  `json:"actor"` // Always "ai-engine"
}

// Alert: AI engine → control plane (informational, no block)
type Alert struct {
	FlowID      uint64  `json:"flow_id"`
	SrcIP       string  `json:"src_ip"`
	Severity    string  `json:"severity"` // "low"|"medium"|"high"|"critical"
	ThreatType  string  `json:"threat_type"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
}

// ErrorMsg: error response
type ErrorMsg struct {
	Code    uint32 `json:"code"`
	Message string `json:"message"`
}

// Error codes
const (
	ErrCodeUnknown        = uint32(1)
	ErrCodeInvalidPayload = uint32(2)
	ErrCodeRateLimited    = uint32(3)
	ErrCodeModelError     = uint32(4)
)
