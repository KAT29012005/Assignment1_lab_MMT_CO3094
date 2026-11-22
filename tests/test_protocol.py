
import io
import os
import sys
import struct
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.protocol import (
    MAGIC, PROTOCOL_VERSION, HEADER_SIZE, MsgType, Flags,
    build_packet, parse_header, recv_packet, send_packet,
    json_payload, parse_json_payload, ProtocolError,
)


class _FakeSocket:
    """Minimal socket stand-in: feed it bytes, recv() pulls from buffer."""

    def __init__(self, data: bytes = b""):
        self._buf = io.BytesIO(data)
        self.sent = b""

    def recv(self, n: int) -> bytes:
        return self._buf.read(n)

    def sendall(self, data: bytes) -> None:
        self.sent += data


class TestHeaderRoundTrip(unittest.TestCase):
    """build_packet + parse_header must produce identical fields."""

    def test_round_trip_basic(self):
        payload = b"hello, world"
        pkt = build_packet(MsgType.MSG_BROADCAST, payload,
                           session_id=12345, flags=Flags.ENCRYPTED)
        self.assertEqual(len(pkt), HEADER_SIZE + len(payload))
        hdr = parse_header(pkt[:HEADER_SIZE])
        self.assertEqual(hdr["magic"], MAGIC)
        self.assertEqual(hdr["msg_type"], MsgType.MSG_BROADCAST)
        self.assertEqual(hdr["flags"], Flags.ENCRYPTED)
        self.assertEqual(hdr["session_id"], 12345)
        self.assertEqual(hdr["payload_len"], len(payload))

    def test_round_trip_empty_payload(self):
        pkt = build_packet(MsgType.HEARTBEAT, b"", session_id=1)
        self.assertEqual(len(pkt), HEADER_SIZE)
        hdr = parse_header(pkt[:HEADER_SIZE])
        self.assertEqual(hdr["payload_len"], 0)

    def test_round_trip_large_payload(self):
        payload = b"x" * 100_000
        pkt = build_packet(MsgType.FILE_CHUNK, payload, session_id=99)
        hdr = parse_header(pkt[:HEADER_SIZE])
        self.assertEqual(hdr["payload_len"], 100_000)


class TestHeaderValidation(unittest.TestCase):
    """Bad magic / oversized payload must raise ProtocolError."""

    def test_bad_magic_rejected(self):
        # Forge a 16-byte header with the wrong magic.
        bad = struct.pack("!HBBII4s", 0xDEAD, 0, 0, 0, 0, b"\x00\x00\x00\x00")
        with self.assertRaises(ProtocolError):
            parse_header(bad)

    def test_too_short_header_rejected(self):
        with self.assertRaises(ProtocolError):
            parse_header(b"\x00\x00")

    def test_oversized_payload_rejected(self):
        # Forge a header that claims a 100 MB payload (above MAX_PAYLOAD)
        bad = struct.pack("!HBBII4s", MAGIC, 0, 0, 0,
                          100 * 1024 * 1024, b"\x00\x00\x00\x00")
        with self.assertRaises(ProtocolError):
            parse_header(bad)


class TestFraming(unittest.TestCase):
    """recv_packet must assemble a complete packet even when recv() returns
    tiny chunks — that is the whole point of length-prefix framing."""

    def test_recv_packet_full(self):
        payload = b"abcdefghij" * 100      # 1 KB
        pkt = build_packet(MsgType.MSG_UNICAST, payload, session_id=7)
        fake = _FakeSocket(pkt)
        hdr, got = recv_packet(fake)
        self.assertEqual(hdr["session_id"], 7)
        self.assertEqual(got, payload)

    def test_recv_packet_chunked_stream(self):
        """Simulate TCP returning 1 byte per recv() — recv_exact must still
        assemble the whole packet."""
        payload = b"PAYLOAD!" * 32
        pkt = build_packet(MsgType.MSG_BROADCAST, payload, session_id=42)

        # Override recv to return 1 byte at a time
        class OneByteSocket(_FakeSocket):
            def recv(self, n):
                return self._buf.read(1)

        fake = OneByteSocket(pkt)
        hdr, got = recv_packet(fake)
        self.assertEqual(hdr["session_id"], 42)
        self.assertEqual(got, payload)

    def test_send_packet_writes_full_bytes(self):
        fake = _FakeSocket()
        send_packet(fake, MsgType.MSG_BROADCAST, b"hi", session_id=5)
        self.assertEqual(len(fake.sent), HEADER_SIZE + 2)
        hdr = parse_header(fake.sent[:HEADER_SIZE])
        self.assertEqual(hdr["msg_type"], MsgType.MSG_BROADCAST)
        self.assertEqual(fake.sent[HEADER_SIZE:], b"hi")


class TestJSONPayload(unittest.TestCase):
    def test_json_round_trip_ascii(self):
        obj = {"username": "alice", "ts": 1.5}
        self.assertEqual(parse_json_payload(json_payload(obj)), obj)

    def test_json_round_trip_vietnamese(self):
        obj = {"text": "Xin chào, thế giới!"}
        self.assertEqual(parse_json_payload(json_payload(obj)), obj)

    def test_empty_payload_returns_empty_dict(self):
        self.assertEqual(parse_json_payload(b""), {})

    def test_invalid_json_raises(self):
        with self.assertRaises(ProtocolError):
            parse_json_payload(b"not json")


if __name__ == "__main__":
    unittest.main()
