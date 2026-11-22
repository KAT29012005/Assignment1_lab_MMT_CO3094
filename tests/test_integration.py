

import os
import sys
import socket
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.server import Server
from client.client import Client
from common.network import DEFAULT_TCP_PORT, DEFAULT_UDP_PORT


def _free_tcp_port() -> int:
    """Pick a free port so parallel test runs do not collide."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestEndToEnd(unittest.TestCase):
    """Two real clients + one real server on loopback."""

    @classmethod
    def setUpClass(cls):
        cls.tcp_port = _free_tcp_port()
        cls.udp_port = _free_tcp_port()
        cls.server = Server(host="127.0.0.1",
                            tcp_port=cls.tcp_port,
                            udp_port=cls.udp_port)
        cls._server_thread = threading.Thread(
            target=cls.server.serve_forever, daemon=True)
        cls._server_thread.start()
        # Give the server a moment to bind + listen
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server._shutdown.set()
        time.sleep(0.2)

    def test_two_clients_handshake_and_chat(self):
        alice = Client(server_host="127.0.0.1",
                       tcp_port=self.tcp_port,
                       udp_port=self.udp_port,
                       download_dir=tempfile.mkdtemp())
        bob = Client(server_host="127.0.0.1",
                     tcp_port=self.tcp_port,
                     udp_port=self.udp_port,
                     download_dir=tempfile.mkdtemp())

        self.assertTrue(alice.login("alice"))
        self.assertTrue(bob.login("bob"))
        self.assertNotEqual(alice.state.session_id, bob.state.session_id)
        self.assertEqual(len(alice.state.aes_key), 32)
        self.assertEqual(len(bob.state.hmac_key), 32)

        # Wait for PRESENCE to propagate
        time.sleep(0.3)

        # Broadcast from Alice
        alice.send_broadcast("hello everyone")
        # Unicast from Alice to Bob
        alice.send_unicast("bob", "hi bob, secret message")

        # Give the receiver threads time to print
        time.sleep(0.5)

        alice.logout()
        bob.logout()


class TestSocketTimeoutRegression(unittest.TestCase):
    """Regression test cho bug #1 và #2 (Báo cáo §11.4 fix #1 & #2).

    Bug #1 (đã sửa): tcp_connect() gọi sock.settimeout(None) sau connect()
    với hiểu nhầm là "trở về default blocking + SO_RCVTIMEO". Thực tế
    settimeout(None) đặt socket ở chế độ NON-BLOCKING, khiến recv() raise
    BlockingIOError (errno 11) liên tục → receiver loop bận CPU 100% và
    dễ bị nhầm là "mất kết nối" chỉ sau 30 giây im lặng.

    Bug #2 (đã sửa): _receiver_loop bắt chung (ConnectionError, OSError)
    mà socket.timeout là subclass của OSError, nên khi recv timeout
    (sau 30s không có packet) client tự ngắt dù server vẫn ổn.
    """

    def setUp(self):
        self.tcp_port = _free_tcp_port()
        self.udp_port = _free_tcp_port()
        self.server = Server("127.0.0.1", self.tcp_port, self.udp_port)
        self._server_thread = threading.Thread(
            target=self.server.serve_forever, daemon=True,
            name="server-regression")
        self._server_thread.start()
        # Đợi server bắt đầu listen (không cần đợi RSA vì Server.__init__
        # đã sinh keypair trước khi serve_forever)
        time.sleep(2.0)

    def tearDown(self):
        self.server._shutdown.set()
        time.sleep(0.2)

    def test_socket_is_blocking_after_connect(self):
        """Sau tcp_connect, socket phải ở chế độ blocking-with-timeout.

        settimeout(None) = non-blocking (SAI). settimeout(positive) =
        blocking-with-timeout (ĐÚNG). gettimeout() phải trả về số dương.
        """
        from common.network import tcp_connect, TCP_RCVTIMEO
        sock = tcp_connect("127.0.0.1", self.tcp_port, timeout=5)
        try:
            to = sock.gettimeout()
            self.assertIsNotNone(
                to, "settimeout(None) đặt non-blocking mode — đây là bug")
            self.assertGreater(
                to, 0, f"timeout phải dương, được {to}")
            self.assertLessEqual(
                abs(to - TCP_RCVTIMEO), 0.1,
                f"timeout phải ≈ TCP_RCVTIMEO={TCP_RCVTIMEO}s, được {to}s")
        finally:
            sock.close()

    def test_receiver_survives_idle_period(self):
        """Client phải vẫn ONLINE sau khi idle > TCP_RCVTIMEO (30s).

        Trước fix: client tự ngắt đúng 30s sau login (BlockingIOError bị
        bắt nhầm thành ConnectionError). Sau fix: receiver loop xử lý
        socket.timeout/BlockingIOError và tiếp tục. Test này rút gọn xuống
        dùng timeout ngắn để chạy nhanh: monkey-patch TCP_RCVTIMEO=2s.
        """
        import common.network as net
        orig_rcvtimeo = net.TCP_RCVTIMEO
        net.TCP_RCVTIMEO = 2.0   # test nhanh: 2 giây thay vì 30
        try:
            alice = Client(server_host="127.0.0.1",
                           tcp_port=self.tcp_port,
                           udp_port=self.udp_port,
                           download_dir=tempfile.mkdtemp())
            self.assertTrue(alice.login("alice_idle"))

            # Đợi vượt quá TCP_RCVTIMEO (2s) — trước fix sẽ disconnect ở đây
            time.sleep(3.5)

            # Socket phải vẫn còn mở (không bị close do nhầm timeout)
            self.assertIsNotNone(
                alice.state.tcp_sock,
                "tcp_sock bị đóng sau idle — bug #1 (non-blocking) hoặc "
                "bug #2 (socket.timeout bị bắt nhầm) vẫn còn")
            # _stop phải False (receiver loop vẫn chạy)
            self.assertFalse(
                alice._stop.is_set(),
                "receiver đã set _stop sau idle — bug chưa được sửa")

            # Tiếp tục idle thêm một chu kỳ nữa để chắc chắn ổn định
            time.sleep(3.5)
            self.assertFalse(alice._stop.is_set(),
                             "receiver ngắt ở chu kỳ thứ 2")

            alice.logout()
        finally:
            net.TCP_RCVTIMEO = orig_rcvtimeo


if __name__ == "__main__":
    unittest.main()
