

import socket
import struct
import errno

# ── Default ports ────────────────────────────────────────────────────────────
DEFAULT_TCP_PORT = 5556     # persistent TCP for messages + file transfer
DEFAULT_UDP_PORT = 5555     # UDP heartbeat / discovery

# ── Timeouts (Báo cáo §9, §11.4) ───────────────────────────────────────────
TCP_RCVTIMEO   = 30          # 30 s — long enough for slow file transfers
UDP_RCVTIMEO   = 15          # 15 s — heartbeat must arrive within 3 cycles
AUTH_TIMEOUT   = 5           # 5 s — see FSM, Báo cáo §6.3


def _set_rcvtimeo(sock: socket.socket, seconds: float) -> None:
    """Set SO_RCVTIMEO cross-platform.

    On Linux SO_RCVTIMEO expects a struct timeval (sec, usec), not a
    millisecond integer. We pack accordingly.
    """
    secs = int(seconds)
    usecs = int((seconds - secs) * 1_000_000)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO,
                    struct.pack("ll", secs, usecs))


def make_tcp_server_socket(host: str, port: int,
                           backlog: int = 32) -> socket.socket:
    """Create a bound, listening TCP server socket.

    SO_REUSEADDR avoids "Address already in use" when restarting the
    server quickly (common during development).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(backlog)
    return sock


def make_tcp_client_socket() -> socket.socket:
    """Create a fresh TCP client socket with a receive timeout."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _set_rcvtimeo(sock, TCP_RCVTIMEO)
    # Enable TCP keepalive (Báo cáo §11.4) — detects half-open connections.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    return sock


def make_udp_socket(bind: tuple = None) -> socket.socket:
    """Create a UDP socket. If `bind` is given, bind to (host, port)
    and allow broadcast (for discovery, see Báo cáo §3)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    _set_rcvtimeo(sock, UDP_RCVTIMEO)
    if bind is not None:
        sock.bind(bind)
    return sock


def tcp_connect(host: str, port: int, timeout: float = AUTH_TIMEOUT) -> socket.socket:
    """Open a TCP connection. Raises ConnectionError on failure.

    Important — semantics của settimeout (Báo cáo §11.4 fix #2):
        Trước đây dòng này gọi sock.settimeout(None) sau connect() với comment
        "back to default (TCP_RCVTIMEO)" — nhưng đó là hiểu SAI semantics:
          • settimeout(None)  → chế độ NON-BLOCKING (recv raise BlockingIOError
                                errno 11 ngay khi không có dữ liệu)
          • settimeout(0)     → cũng non-blocking
          • settimeout(>0)    → blocking với timeout (raise socket.timeout khi
                                hết thời gian — đây mới là điều ta muốn)
        Vì vậy SO_RCVTIMEO đã set trong make_tcp_client_socket() bị bỏ qua
        hoàn toàn, receiver loop liên tục raise BlockingIOError và client
        bận CPU 100% + dễ bị nhầm là "mất kết nối". Fix: set timeout dương
        bằng TCP_RCVTIMEO sau khi connect.
    """
    sock = make_tcp_client_socket()
    try:
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.settimeout(TCP_RCVTIMEO)   # blocking + timeout (không phải None)
        return sock
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        sock.close()
        raise ConnectionError(f"cannot connect to {host}:{port}: {exc}") from exc


def safe_sendall(sock: socket.socket, data: bytes) -> bool:
    """sendall() that never raises — returns True on success, False on
    a dropped peer (BrokenPipeError / ConnectionResetError).

    Used by the broadcast router (Báo cáo §11.3): we wrap each send in
    its own try/except so one dead client does not abort the loop.
    """
    try:
        sock.sendall(data)
        return True
    except (BrokenPipeError, ConnectionResetError, OSError):
        return False
