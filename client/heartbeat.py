
import socket
import threading
import time

from common.protocol import (
    MsgType, build_packet, json_payload, now_ts,
)
from common.network import DEFAULT_UDP_PORT


HEARTBEAT_INTERVAL = 5.0     # seconds — 3 missed = 15s (still under TTL=60s)


class HeartbeatSender:
    """Background thread that sends UDP HEARTBEAT packets to the server."""

    def __init__(self, server_host: str, server_port: int = DEFAULT_UDP_PORT,
                 session_id: int = 0, interval: float = HEARTBEAT_INTERVAL):
        self.server_addr = (server_host, server_port)
        self.session_id = session_id
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sock: socket.socket | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="heartbeat")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                pkt = build_packet(
                    MsgType.HEARTBEAT,
                    json_payload({"session_id": self.session_id, "ts": now_ts()}),
                    session_id=self.session_id,
                )
                if self._sock:
                    self._sock.sendto(pkt, self.server_addr)
            except OSError:
                # Network down? Skip this round and try again next interval.
                pass
            self._stop.wait(self.interval)
