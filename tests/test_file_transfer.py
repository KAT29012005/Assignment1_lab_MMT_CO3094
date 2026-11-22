

import os
import sys
import socket
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.file_transfer import send_file, receive_file, file_metadata, iter_chunks
from common.protocol import CHUNK_SIZE


class _SocketPair:
    """Wraps socket.socketpair for use as (sender_sock, receiver_sock)."""

    def __init__(self):
        self.a, self.b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

    def close(self):
        try: self.a.close()
        except OSError: pass
        try: self.b.close()
        except OSError: pass


class TestFileMetadata(unittest.TestCase):
    def test_metadata_basic(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
            tmp.write(b"x" * (CHUNK_SIZE * 3 + 100))
            path = tmp.name
        try:
            meta = file_metadata(path)
            self.assertEqual(meta["size"], CHUNK_SIZE * 3 + 100)
            self.assertEqual(meta["chunks"], 4)
            self.assertEqual(len(meta["sha256"]), 64)
            self.assertIn("filename", meta)
        finally:
            os.remove(path)

    def test_iter_chunks_count_matches(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
            tmp.write(b"y" * (CHUNK_SIZE * 2))
            path = tmp.name
        try:
            chunks = list(iter_chunks(path))
            self.assertEqual(len(chunks), 2)
            self.assertEqual(chunks[0][0], 0)
            self.assertEqual(chunks[1][0], 1)
        finally:
            os.remove(path)


class TestSendReceiveFile(unittest.TestCase):
    """End-to-end: send_file on one socket, receive_file on the other."""

    def _run_transfer(self, content: bytes, dest_dir: str) -> str:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
            tmp.write(content)
            src_path = tmp.name
        pair = _SocketPair()
        try:
            received_path_holder = {"path": None, "err": None}

            def receiver_thread():
                try:
                    received_path_holder["path"] = receive_file(
                        pair.b, dest_dir, session_id=0)
                except Exception as exc:   # noqa: BLE001
                    received_path_holder["err"] = exc

            t = threading.Thread(target=receiver_thread)
            t.start()
            send_file(pair.a, src_path, session_id=0)
            t.join(timeout=10)

            self.assertIsNone(received_path_holder["err"],
                              f"receiver raised: {received_path_holder['err']}")
            self.assertIsNotNone(received_path_holder["path"])
            return received_path_holder["path"]
        finally:
            pair.close()
            os.remove(src_path)

    def test_small_file_round_trip(self):
        content = b"hello, file transfer!"
        with tempfile.TemporaryDirectory() as dest_dir:
            saved = self._run_transfer(content, dest_dir)
            with open(saved, "rb") as fh:
                self.assertEqual(fh.read(), content)

    def test_exact_one_chunk(self):
        content = b"A" * CHUNK_SIZE
        with tempfile.TemporaryDirectory() as dest_dir:
            saved = self._run_transfer(content, dest_dir)
            with open(saved, "rb") as fh:
                self.assertEqual(fh.read(), content)

    def test_multi_chunk_round_trip(self):
        content = b"B" * (CHUNK_SIZE * 5 + 137)
        with tempfile.TemporaryDirectory() as dest_dir:
            saved = self._run_transfer(content, dest_dir)
            with open(saved, "rb") as fh:
                self.assertEqual(fh.read(), content)

    def test_binary_random_content(self):
        content = os.urandom(50_000)
        with tempfile.TemporaryDirectory() as dest_dir:
            saved = self._run_transfer(content, dest_dir)
            with open(saved, "rb") as fh:
                self.assertEqual(fh.read(), content)


if __name__ == "__main__":
    unittest.main()
