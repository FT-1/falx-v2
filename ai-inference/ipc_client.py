# =============================================================================
# Project: FALX V2
# Lead Architect & Owner: FT-1
# Description: Python IPC client (ai-inference/ipc_client.py).
#              Python-side implementation of the FLX2 wire protocol.
#              Used when the AI inference layer is implemented in Python
#              (e.g. scikit-learn, PyTorch models) rather than C++.
#
#              Fully async (asyncio) for integration with async ML frameworks.
#              Implements the same protocol as ipc_protocol.hpp and protocol.go.
# =============================================================================

from __future__ import annotations

import asyncio
import json
import logging
import struct
import zlib
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Awaitable, Optional

log = logging.getLogger("falx.ipc")

# ─── Constants ────────────────────────────────────────────────────────────────
MAGIC_BYTES      = b'\x46\x4C\x58\x32'  # "FLX2"
PROTOCOL_VERSION = 1
HEADER_SIZE      = 20
MAX_PAYLOAD_SIZE = 1 << 20  # 1 MiB

# Header format: magic(4s) version(B) type(B) flags(H) seq(I) len(I) crc32(I)
# All multi-byte fields are LITTLE-ENDIAN
HEADER_FMT    = '<4sBBHIII'
assert struct.calcsize(HEADER_FMT) == HEADER_SIZE


# ─── Message Types ────────────────────────────────────────────────────────────
class MsgType(IntEnum):
    InferRequest  = 0x01
    ConfigPush    = 0x02
    Heartbeat     = 0x03
    InferResponse = 0x81
    MapUpdateReq  = 0x82
    HeartbeatAck  = 0x83
    Alert         = 0x84
    Error         = 0xFF


# ─── Flags ────────────────────────────────────────────────────────────────────
FLAG_ACK_REQUIRED = 1 << 2


# ─── Frame ────────────────────────────────────────────────────────────────────
@dataclass
class Frame:
    msg_type: MsgType
    seq:      int
    flags:    int
    payload:  bytes = field(default=b'')

    @property
    def crc32(self) -> int:
        hdr = self._pack_header(crc32=0)
        return zlib.crc32(hdr[:16] + self.payload) & 0xFFFFFFFF

    def _pack_header(self, crc32: int = 0) -> bytes:
        return struct.pack(
            HEADER_FMT,
            MAGIC_BYTES,
            PROTOCOL_VERSION,
            int(self.msg_type),
            self.flags,
            self.seq,
            len(self.payload),
            crc32,
        )

    def serialise(self) -> bytes:
        crc = self.crc32
        return self._pack_header(crc) + self.payload

    @classmethod
    def from_bytes(cls, hdr_bytes: bytes, payload: bytes) -> 'Frame':
        magic, version, mtype, flags, seq, plen, crc32 = struct.unpack(
            HEADER_FMT, hdr_bytes
        )
        if magic != MAGIC_BYTES:
            raise ValueError(f"Invalid magic: {magic!r}")
        if version != PROTOCOL_VERSION:
            raise ValueError(f"Unsupported protocol version: {version}")

        frame = cls(
            msg_type=MsgType(mtype),
            seq=seq,
            flags=flags,
            payload=payload,
        )
        # Verify CRC
        expected = frame.crc32
        if crc32 != expected:
            raise ValueError(f"CRC mismatch: got 0x{crc32:08x}, expected 0x{expected:08x}")
        return frame


def build_frame(msg_type: MsgType, seq: int, payload_obj: object = None,
                flags: int = 0) -> Frame:
    payload = b''
    if payload_obj is not None:
        payload = json.dumps(payload_obj, separators=(',', ':')).encode()
        flags |= FLAG_ACK_REQUIRED
    return Frame(msg_type=msg_type, seq=seq, flags=flags, payload=payload)


# ─── Async IPC Client ─────────────────────────────────────────────────────────
class AsyncIPCClient:
    """
    Async IPC client for Python-side AI inference workers.
    Connects to falxd's Unix domain socket and handles the FLX2 protocol.
    """

    def __init__(self, socket_path: str = '/var/run/falx/ai.sock') -> None:
        self.socket_path = socket_path
        self._reader: Optional[asyncio.StreamReader]  = None
        self._writer: Optional[asyncio.StreamWriter]  = None
        self._seq     = 0
        self._running = False

        # Callback: called when CP sends an InferRequest
        self.on_infer_request: Optional[Callable[[dict], Awaitable[None]]] = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    async def connect(self) -> None:
        self._reader, self._writer = await asyncio.open_unix_connection(
            path=self.socket_path
        )
        self._running = True
        log.info("Connected to falxd IPC socket: %s", self.socket_path)

    async def disconnect(self) -> None:
        self._running = False
        if self._writer:
            self._writer.close()
            await self._writer.wait_closed()

    async def run(self) -> None:
        """Main loop: read frames and dispatch. Call after connect()."""
        hb_task = asyncio.create_task(self._heartbeat_loop())
        try:
            while self._running:
                try:
                    frame = await self._read_frame()
                    await self._dispatch(frame)
                except asyncio.IncompleteReadError:
                    log.info("IPC connection closed by server")
                    break
                except Exception as exc:
                    log.error("Frame error: %s", exc)
        finally:
            hb_task.cancel()

    # ── AI → CP: Block request ────────────────────────────────────────────────
    async def send_block(
        self, src_ip: str, action: int, threat_score: int,
        rule_id: int, ttl_seconds: int, reason: str
    ) -> None:
        payload = {
            'src_ip': src_ip, 'action': action,
            'threat_score': threat_score, 'rule_id': rule_id,
            'ttl_s': ttl_seconds, 'reason': reason,
            'actor': 'ai-engine',
        }
        frame = build_frame(MsgType.MapUpdateReq, self._next_seq(), payload)
        await self._send_frame(frame)
        log.info("Block request sent: %s action=%d score=%d", src_ip, action, threat_score)

    # ── AI → CP: Alert ────────────────────────────────────────────────────────
    async def send_alert(
        self, flow_id: int, src_ip: str, severity: str,
        threat_type: str, confidence: float, description: str
    ) -> None:
        payload = {
            'flow_id': flow_id, 'src_ip': src_ip,
            'severity': severity, 'threat_type': threat_type,
            'confidence': confidence, 'description': description,
        }
        frame = build_frame(MsgType.Alert, self._next_seq(), payload)
        await self._send_frame(frame)

    # ── AI → CP: Inference Response ───────────────────────────────────────────
    async def send_infer_response(self, request_id: int, verdicts: list) -> None:
        payload = {'request_id': request_id, 'verdicts': verdicts}
        frame   = build_frame(MsgType.InferResponse, self._next_seq(), payload)
        await self._send_frame(frame)

    # ── Internal ──────────────────────────────────────────────────────────────
    async def _read_frame(self) -> Frame:
        hdr_bytes = await self._reader.readexactly(HEADER_SIZE)
        _, _, _, _, _, plen, _ = struct.unpack(HEADER_FMT, hdr_bytes)

        if plen > MAX_PAYLOAD_SIZE:
            raise ValueError(f"Payload {plen} exceeds max {MAX_PAYLOAD_SIZE}")

        payload = await self._reader.readexactly(plen) if plen > 0 else b''
        return Frame.from_bytes(hdr_bytes, payload)

    async def _send_frame(self, frame: Frame) -> None:
        self._writer.write(frame.serialise())
        await self._writer.drain()

    async def _dispatch(self, frame: Frame) -> None:
        if frame.msg_type == MsgType.InferRequest:
            if self.on_infer_request and frame.payload:
                req = json.loads(frame.payload)
                await self.on_infer_request(req)

        elif frame.msg_type == MsgType.Heartbeat:
            ack = Frame(MsgType.HeartbeatAck, seq=frame.seq, flags=0)
            await self._send_frame(ack)
            log.debug("Heartbeat → ACK (seq=%d)", frame.seq)

        elif frame.msg_type == MsgType.Error:
            err = json.loads(frame.payload) if frame.payload else {}
            log.warning("Error from falxd: code=%s msg=%s",
                        err.get('code'), err.get('message'))

    async def _heartbeat_loop(self) -> None:
        while self._running:
            await asyncio.sleep(5)
            try:
                frame = Frame(MsgType.Heartbeat, seq=self._next_seq(), flags=0)
                await self._send_frame(frame)
            except Exception:
                break

    def _next_seq(self) -> int:
        self._seq = (self._seq + 1) & 0xFFFFFFFF
        return self._seq


# ─── Action Constants (mirror bpfmaps) ────────────────────────────────────────
class Action(IntEnum):
    Pass       = 1
    Drop       = 2
    Redirect   = 3
    RateLimit  = 4
