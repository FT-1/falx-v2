// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: IPC protocol header (ai-inference/src/ipc_protocol.hpp).
//              C++ mirror of control-plane/internal/ipc/protocol.go.
//              Byte-for-byte identical frame layout (little-endian).
//              Used by the AI inference engine to communicate with falxd.
// =============================================================================

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <stdexcept>
#include <vector>

namespace falx::ipc {

// ─── Constants ────────────────────────────────────────────────────────────────
constexpr std::array<uint8_t, 4> MAGIC_BYTES = {0x46, 0x4C, 0x58, 0x32}; // "FLX2"
constexpr uint8_t  PROTOCOL_VERSION = 1;
constexpr size_t   HEADER_SIZE      = 20;
constexpr uint32_t MAX_PAYLOAD_SIZE = 1u << 20; // 1 MiB

// ─── Message Types ────────────────────────────────────────────────────────────
enum class MsgType : uint8_t {
    // Control plane → AI engine
    InferRequest  = 0x01,
    ConfigPush    = 0x02,
    Heartbeat     = 0x03,

    // AI engine → Control plane
    InferResponse = 0x81,
    MapUpdateReq  = 0x82,
    HeartbeatAck  = 0x83,
    Alert         = 0x84,

    // Bidirectional
    Error         = 0xFF,
};

// ─── Frame Flags ──────────────────────────────────────────────────────────────
constexpr uint16_t FLAG_COMPRESSED   = 1u << 0;
constexpr uint16_t FLAG_ENCRYPTED    = 1u << 1;
constexpr uint16_t FLAG_ACK_REQUIRED = 1u << 2;

// ─── Frame Header (20 bytes, little-endian) ───────────────────────────────────
// MUST match exactly:
//   Magic:   [4]byte  offset 0
//   Version: uint8    offset 4
//   Type:    uint8    offset 5
//   Flags:   uint16   offset 6  (LE)
//   Seq:     uint32   offset 8  (LE)
//   Len:     uint32   offset 12 (LE)
//   CRC32:   uint32   offset 16 (LE)
#pragma pack(push, 1)
struct FrameHeader {
    uint8_t  magic[4];
    uint8_t  version;
    uint8_t  type;       // MsgType
    uint16_t flags;      // little-endian
    uint32_t seq;        // little-endian
    uint32_t len;        // payload length, little-endian
    uint32_t crc32;      // little-endian
};
static_assert(sizeof(FrameHeader) == HEADER_SIZE, "FrameHeader must be 20 bytes");
#pragma pack(pop)

// ─── Frame (header + payload) ─────────────────────────────────────────────────
struct Frame {
    FrameHeader         header;
    std::vector<uint8_t> payload;
};

// ─── CRC32 (IEEE polynomial, matches Go's hash/crc32.NewIEEE()) ───────────────
namespace detail {
    constexpr uint32_t CRC32_POLY = 0xEDB88320u;

    inline uint32_t crc32_compute(const uint8_t* data, size_t len) {
        uint32_t crc = 0xFFFFFFFFu;
        for (size_t i = 0; i < len; ++i) {
            crc ^= data[i];
            for (int j = 0; j < 8; ++j) {
                crc = (crc >> 1) ^ (-(crc & 1) & CRC32_POLY);
            }
        }
        return crc ^ 0xFFFFFFFFu;
    }
} // namespace detail

// ─── Frame Builder ────────────────────────────────────────────────────────────
inline Frame build_frame(
    MsgType type,
    uint32_t seq,
    uint16_t flags,
    const uint8_t* payload_data,
    uint32_t payload_len
) {
    Frame frame;
    frame.payload.assign(payload_data, payload_data + payload_len);

    FrameHeader& h = frame.header;
    std::memcpy(h.magic, MAGIC_BYTES.data(), 4);
    h.version = PROTOCOL_VERSION;
    h.type    = static_cast<uint8_t>(type);
    h.flags   = flags;
    h.seq     = seq;
    h.len     = payload_len;

    // CRC32 covers header[0:16] + payload
    uint8_t hdr_bytes[HEADER_SIZE] = {};
    std::memcpy(hdr_bytes, &h, HEADER_SIZE);
    // Zero out CRC field before computing
    std::memset(hdr_bytes + 16, 0, 4);

    uint32_t crc = detail::crc32_compute(hdr_bytes, 16);
    if (payload_len > 0) {
        // Continue CRC over payload
        uint32_t crc2 = 0xFFFFFFFFu;
        // Combine: feed payload into existing CRC state
        // For simplicity: compute over combined buffer
        std::vector<uint8_t> combined(16 + payload_len);
        std::memcpy(combined.data(), hdr_bytes, 16);
        std::memcpy(combined.data() + 16, payload_data, payload_len);
        crc = detail::crc32_compute(combined.data(), combined.size());
    }
    h.crc32 = crc;

    return frame;
}

inline Frame build_frame(MsgType type, uint32_t seq, const std::string& json_payload) {
    return build_frame(type, seq, FLAG_ACK_REQUIRED,
        reinterpret_cast<const uint8_t*>(json_payload.data()),
        static_cast<uint32_t>(json_payload.size()));
}

// ─── Frame Serialiser ─────────────────────────────────────────────────────────
inline std::vector<uint8_t> serialise(const Frame& frame) {
    std::vector<uint8_t> buf(HEADER_SIZE + frame.payload.size());

    // Write header (little-endian fields)
    std::memcpy(buf.data(), frame.header.magic, 4);
    buf[4] = frame.header.version;
    buf[5] = frame.header.type;

    auto write_le16 = [&](size_t off, uint16_t v) {
        buf[off]   = v & 0xFF;
        buf[off+1] = (v >> 8) & 0xFF;
    };
    auto write_le32 = [&](size_t off, uint32_t v) {
        buf[off]   =  v        & 0xFF;
        buf[off+1] = (v >> 8)  & 0xFF;
        buf[off+2] = (v >> 16) & 0xFF;
        buf[off+3] = (v >> 24) & 0xFF;
    };

    write_le16(6,  frame.header.flags);
    write_le32(8,  frame.header.seq);
    write_le32(12, frame.header.len);
    write_le32(16, frame.header.crc32);

    std::memcpy(buf.data() + HEADER_SIZE, frame.payload.data(), frame.payload.size());
    return buf;
}

// ─── Frame Parser ─────────────────────────────────────────────────────────────
inline Frame parse_frame(const uint8_t* data, size_t total_len) {
    if (total_len < HEADER_SIZE) {
        throw std::runtime_error("buffer too small for frame header");
    }

    Frame frame;
    FrameHeader& h = frame.header;

    std::memcpy(h.magic, data, 4);
    if (std::memcmp(h.magic, MAGIC_BYTES.data(), 4) != 0) {
        throw std::runtime_error("invalid magic bytes");
    }

    h.version = data[4];
    if (h.version != PROTOCOL_VERSION) {
        throw std::runtime_error("unsupported protocol version");
    }

    h.type = data[5];

    auto read_le16 = [&](size_t off) -> uint16_t {
        return static_cast<uint16_t>(data[off]) |
               (static_cast<uint16_t>(data[off+1]) << 8);
    };
    auto read_le32 = [&](size_t off) -> uint32_t {
        return static_cast<uint32_t>(data[off])        |
               (static_cast<uint32_t>(data[off+1]) << 8)  |
               (static_cast<uint32_t>(data[off+2]) << 16) |
               (static_cast<uint32_t>(data[off+3]) << 24);
    };

    h.flags = read_le16(6);
    h.seq   = read_le32(8);
    h.len   = read_le32(12);
    h.crc32 = read_le32(16);

    if (h.len > MAX_PAYLOAD_SIZE) {
        throw std::runtime_error("payload size exceeds maximum");
    }
    if (total_len < HEADER_SIZE + h.len) {
        throw std::runtime_error("buffer too small for payload");
    }

    frame.payload.assign(data + HEADER_SIZE, data + HEADER_SIZE + h.len);
    return frame;
}

// ─── Error Codes ──────────────────────────────────────────────────────────────
constexpr uint32_t ERR_UNKNOWN         = 1;
constexpr uint32_t ERR_INVALID_PAYLOAD = 2;
constexpr uint32_t ERR_RATE_LIMITED    = 3;
constexpr uint32_t ERR_MODEL_ERROR     = 4;

} // namespace falx::ipc
