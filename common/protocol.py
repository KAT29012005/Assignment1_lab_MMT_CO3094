

import json
import socket
import struct
import time
from enum import IntEnum

# ── Protocol constants ──────────────────────────────────────────────────────
PROTOCOL_VERSION = 1
MAGIC = 0xCA51                       # see Báo cáo §6.1, Bảng 1
# Layout (16 bytes, network / big-endian):
#   ! H  B  B  I  I  4s
#     |  |  |  |  |  └── RESERVED (4 bytes padding for 4-byte alignment)
#     |  |  |  └───── PAYLOAD_LEN (4 bytes, unsigned int)
#     |  |  └──────── SESSION_ID (4 bytes, unsigned int)
#     |  └────────── FLAGS (1 byte, full 8 bits — EOM/ENCRYPTED/COMPRESSED)
#     └──────────── MAGIC (2 bytes, 0xCA51)
#
# Note: the MSG_TYPE byte (8 bits, supporting the 10 codes from 0x01 to 0xF0
# in Bảng 2) and the FLAGS byte (8 bits) occupy two distinct fields, with no
# separate VERSION field (the MAGIC implicitly identifies the protocol
# version). The 4-byte RESERVED field keeps the header 4-byte aligned for
# efficient parser access.
HEADER_FORMAT = "!HBBI4s"           # 2+1+1+4+4+4 = 16 bytes
# Wait — that's only 6 fields. Real layout: H B B I I 4s = 6 fields, 16 bytes.
# Let's expand to match Bảng 1 exactly.
HEADER_FORMAT = "!HBBII4s"          # 2+1+1+4+4+4 = 16 bytes (final)
HEADER_SIZE = 16
MAX_PAYLOAD = 10 * 1024 * 1024       # 10 MB hard cap (defense in depth)
CHUNK_SIZE = 8 * 1024                # 8 KB file chunk (see Báo cáo §6.2)


class MsgType(IntEnum):
    """Message type codes (see Bảng 2 in Báo cáo)."""
    AUTH          = 0x01    # client -> server: {username, pubkey_pem}
    AUTH_ACK      = 0x02    # server -> client: {session_id, server_pubkey, K_S enc}
    PRESENCE      = 0x10    # server -> client: list of active users
    MSG_BROADCAST = 0x20    # client -> server -> all: {from, text, ts}
    MSG_UNICAST   = 0x21    # client -> server -> client: {from, to, text, ts}
    FILE_INIT     = 0x30    # client -> server -> client: {filename, size, chunks, sha256}
    FILE_CHUNK    = 0x31    # client -> server -> client: raw 8 KB chunk
    FILE_ACK      = 0x32    # client -> server: {chunk_id, ok: bool}
    HEARTBEAT     = 0x40    # client -> server (UDP): {session_id, ts}
    ERROR         = 0xF0    # server -> client: {code, message}


class Flags:
    EOM        = 0x01       # End-Of-Message marker (for multi-segment payloads)
    ENCRYPTED  = 0x02       # Payload is AES-encrypted
    COMPRESSED = 0x04       # Payload is gzip-compressed (reserved, future)


class ProtocolError(Exception):
    """Raised when a packet fails validation."""


# ── Packet builder / parser ──────────────────────────────────────────────────

def build_packet(msg_type: int, payload: bytes, session_id: int = 0,
                 flags: int = 0) -> bytes:
    """Serialize a packet: 16-byte header + payload.

    Header layout (Bảng 1, mục 6.1) — exactly 16 bytes:
      offset 0:  MAGIC       (2 bytes, 0xCA51)
      offset 2:  MSG_TYPE    (1 byte, supports 0x01–0xF0 from Bảng 2)
      offset 3:  FLAGS       (1 byte, bitfield: EOM | ENCRYPTED | COMPRESSED)
      offset 4:  SESSION_ID  (4 bytes, big-endian unsigned int)
      offset 8:  PAYLOAD_LEN (4 bytes, big-endian unsigned int)
      offset 12: RESERVED    (4 bytes, padding for 4-byte alignment)
      offset 16: PAYLOAD     (variable)

    No separate VERSION field — the MAGIC implicitly identifies the
    protocol version (changing the protocol bumps MAGIC).
    """
    if len(payload) > MAX_PAYLOAD:
        raise ProtocolError(f"payload too large: {len(payload)} > {MAX_PAYLOAD}")
    if session_id < 0 or session_id > 0xFFFFFFFF:
        raise ProtocolError(f"session_id out of range: {session_id}")
    if msg_type < 0 or msg_type > 0xFF:
        raise ProtocolError(f"msg_type out of range: {msg_type}")
    if flags < 0 or flags > 0xFF:
        raise ProtocolError(f"flags out of range: {flags}")
    header = struct.pack(
        HEADER_FORMAT,
        MAGIC,
        msg_type,
        flags,
        session_id,
        len(payload),
        b"\x00\x00\x00\x00",
    )
    return header + payload


def parse_header(data: bytes):
    """Parse the first 16 bytes of a packet. Returns a dict of fields."""
    if len(data) < HEADER_SIZE:
        raise ProtocolError("header too short")
    (magic, msg_type, flags, session_id,
     payload_len, _reserved) = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
    if magic != MAGIC:
        raise ProtocolError(f"bad magic: 0x{magic:04X} (expected 0x{MAGIC:04X})")
    if payload_len > MAX_PAYLOAD:
        raise ProtocolError(f"payload_len too large: {payload_len}")
    return {
        "magic": magic,
        "msg_type": msg_type,
        "flags": flags,
        "session_id": session_id,
        "payload_len": payload_len,
    }


# ── Length-prefix framing (TCP byte stream) ──────────────────────────────────

def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from a TCP socket.

    TCP is a byte stream (Ch.3 slide 80), not a message stream — a single
    recv() may return fewer bytes than requested. This helper loops until
    n bytes are accumulated or the socket closes.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed before n bytes received")
        buf.extend(chunk)
    return bytes(buf)


def recv_packet(sock: socket.socket):
    """Read one full packet (header + payload) from a TCP socket.

    Returns (header_dict, payload_bytes).
    """
    header_bytes = recv_exact(sock, HEADER_SIZE)
    hdr = parse_header(header_bytes)
    payload = recv_exact(sock, hdr["payload_len"]) if hdr["payload_len"] else b""
    return hdr, payload


def send_packet(sock: socket.socket, msg_type: int, payload: bytes,
                session_id: int = 0, flags: int = 0) -> None:
    """Build and send a packet on a TCP socket."""
    sock.sendall(build_packet(msg_type, payload, session_id, flags))


# ── JSON payload helpers (control messages) ─────────────────────────────────

def json_payload(obj: dict) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


def parse_json_payload(payload: bytes) -> dict:
    if not payload:
        return {}
    try:
        return json.loads(payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ProtocolError(f"invalid JSON payload: {exc}") from exc


def now_ts() -> float:
    """Unix timestamp (seconds) — used in message envelopes."""
    return time.time()
