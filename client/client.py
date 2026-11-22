

import os
import socket
import sys
import threading
import traceback

sys.path.insert(0, __file__[:__file__.rfind("/client/")] if "/client/" in __file__ else ".")

from common.protocol import (
    MsgType, Flags, build_packet, send_packet, recv_packet,
    json_payload, parse_json_payload, now_ts, parse_header, HEADER_SIZE,
)
from common.crypto import (
    generate_rsa_keypair, serialize_public_key,
    decrypt_session_keys, encrypt_payload, decrypt_payload,
)
from common.network import (
    DEFAULT_TCP_PORT, DEFAULT_UDP_PORT, AUTH_TIMEOUT,
    tcp_connect,
)
from common.file_transfer import send_file, receive_file
from client.heartbeat import HeartbeatSender


class ClientState:
    """Holds the client's per-session state shared across threads."""
    def __init__(self):
        self.session_id: int = 0
        self.username: str = ""
        self.aes_key: bytes = b""
        self.hmac_key: bytes = b""
        self.tcp_sock: socket.socket | None = None
        self._crypto_lock = threading.Lock()

    def encrypt(self, plaintext: bytes) -> tuple:
        """Encrypt under the session keys. Returns (payload, flags)."""
        with self._crypto_lock:
            return (encrypt_payload(plaintext, self.aes_key, self.hmac_key),
                    Flags.ENCRYPTED)

    def decrypt(self, payload: bytes) -> bytes:
        with self._crypto_lock:
            return decrypt_payload(payload, self.aes_key, self.hmac_key)


class Client:
    def __init__(self, server_host: str = "127.0.0.1",
                 tcp_port: int = DEFAULT_TCP_PORT,
                 udp_port: int = DEFAULT_UDP_PORT,
                 download_dir: str = "./downloads"):
        self.server_host = server_host
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.download_dir = download_dir
        self.state = ClientState()
        self.heartbeat: HeartbeatSender | None = None
        self._receiver_thread: threading.Thread | None = None
        self._stop = threading.Event()

    # ── Connect + AUTH ────────────────────────────────────────────────────

    def login(self, username: str) -> bool:
        """Open TCP, send AUTH, decrypt AUTH_ACK. Returns True on success."""
        sock = tcp_connect(self.server_host, self.tcp_port, timeout=AUTH_TIMEOUT)
        self.state.tcp_sock = sock

        # 1. Generate a fresh RSA-2048 keypair for this session (Ch.8 S21-25)
        priv, pub = generate_rsa_keypair()
        self._rsa_priv = priv

        # 2. Send AUTH
        auth_payload = json_payload({
            "username": username,
            "pubkey_pem": serialize_public_key(pub).decode("utf-8"),
        })
        send_packet(sock, MsgType.AUTH, auth_payload)

        # 3. Receive AUTH_ACK (timeout handled by tcp_connect/SO_RCVTIMEO)
        hdr, payload = recv_packet(sock)
        if hdr["msg_type"] != MsgType.AUTH_ACK:
            print(f"[client] expected AUTH_ACK, got 0x{hdr['msg_type']:02X}")
            return False
        ack = parse_json_payload(payload)
        self.state.session_id = ack["session_id"]
        self.state.username = username

        # 4. Decrypt K_S with the client's RSA private key (Ch.8 S22, S28)
        enc_keys = bytes.fromhex(ack["encrypted_session_keys_b64"])
        self.state.aes_key, self.state.hmac_key = decrypt_session_keys(
            enc_keys, self._rsa_priv)
        print(f"[client] AUTH ok — session_id={self.state.session_id}, "
              f"K_S established (AES-256 + HMAC-SHA256)")

        # 5. Start heartbeat + receiver threads
        self.heartbeat = HeartbeatSender(self.server_host, self.udp_port,
                                         self.state.session_id)
        self.heartbeat.start()
        self._receiver_thread = threading.Thread(
            target=self._receiver_loop, daemon=True, name="receiver")
        self._receiver_thread.start()
        return True

    def logout(self) -> None:
        """Graceful shutdown."""
        self._stop.set()
        if self.heartbeat:
            self.heartbeat.stop()
        if self.state.tcp_sock:
            try:
                self.state.tcp_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.state.tcp_sock.close()
            except OSError:
                pass
        print("[client] disconnected")

    # ── Receiver thread ─────────────────────────────────────────────────

    def _receiver_loop(self) -> None:
        """Background thread that prints incoming MSG / PRESENCE / FILE.

        Important — xử lý socket.timeout (Báo cáo §9, §11.4):
            Sockets TCP được set SO_RCVTIMEO=30s (common/network.py:TCP_RCVTIMEO)
            để receiver không block vĩnh viễn. Khi hết 30s mà không nhận được
            packet nào (không có chat activity), recv_packet() raise
            socket.timeout — đây KHÔNG phải lỗi, chỉ là "không có dữ liệu".
            Phải bắt riêng socket.timeout (subclass của OSError) và loop tiếp;
            nếu bắt chung OSError thì client sẽ tự ngắt sau 30s im lặng dù
            server vẫn ổn định. Đây là bug đã được sửa (Báo cáo §11.4 fix #1).
        """
        sock = self.state.tcp_sock
        while not self._stop.is_set():
            try:
                hdr, payload = recv_packet(sock)
            except socket.timeout:
                # Hết SO_RCVTIMEO mà không có packet — bình thường, loop tiếp.
                continue
            except (ConnectionError, OSError):
                if not self._stop.is_set():
                    print("[client] connection closed by server")
                    self._stop.set()
                break

            try:
                if hdr["flags"] & Flags.ENCRYPTED:
                    payload = self.state.decrypt(payload)

                if hdr["msg_type"] == MsgType.MSG_BROADCAST:
                    env = parse_json_payload(payload)
                    print(f"\n[broadcast] {env.get('from','?')}: "
                          f"{env.get('text','')}")
                elif hdr["msg_type"] == MsgType.MSG_UNICAST:
                    env = parse_json_payload(payload)
                    print(f"\n[private] {env.get('from','?')}: "
                          f"{env.get('text','')}")
                elif hdr["msg_type"] == MsgType.PRESENCE:
                    env = parse_json_payload(payload)
                    users = [u["username"] for u in env.get("users", [])]
                    print(f"\n[presence] active users ({len(users)}): "
                          f"{', '.join(users) if users else '(none)'}")
                elif hdr["msg_type"] == MsgType.FILE_INIT:
                    # Incoming file: switch to receive_file() helper, which
                    # drives the stop-and-wait protocol on this same socket.
                    os.makedirs(self.download_dir, exist_ok=True)
                    # Re-pack the FILE_INIT for receive_file (it expects
                    # to read it itself), so just call receive_file with a
                    # pre-peeked header — simplified here: re-send a fake
                    # ACK to start. For the lab, files are typically sent
                    # one direction; full bidirectional receive is left as
                    # an exercise. We instead route the FILE_INIT back to
                    # receive_file() by buffering.
                    self._handle_incoming_file(hdr, payload)
                elif hdr["msg_type"] == MsgType.ERROR:
                    env = parse_json_payload(payload)
                    print(f"\n[error] code={env.get('code')}: "
                          f"{env.get('message')}")
                else:
                    print(f"\n[client] unhandled msg_type "
                          f"0x{hdr['msg_type']:02X}")
            except Exception as exc:        # noqa: BLE001
                print(f"\n[client] receiver error: {exc}")
                traceback.print_exc()

    def _handle_incoming_file(self, hdr: dict, init_payload: bytes) -> None:
        """Drive the receive_file() state machine for an incoming file.

        We have already consumed the FILE_INIT; we replay it into a small
        in-memory buffer so receive_file() can read the same packet flow.
        The simplified approach for this lab: skip the re-buffering and
        just write the file using the metadata we have, accepting the next
        N FILE_CHUNK packets inline. For a cleaner abstraction, see the
        `examples/demo_send_file.py` script which uses send_file/receive_file
        back-to-back.
        """
        # NOTE: Full bidirectional receive reuses receive_file()'s loop,
        # which expects to read FILE_INIT first. To keep this demo simple,
        # we acknowledge the FILE_INIT then drain chunks directly here.
        meta = parse_json_payload(init_payload)
        filename = os.path.basename(meta.get("filename", "received"))
        dest = os.path.join(self.download_dir, filename)
        total = meta.get("chunks", 0)
        print(f"\n[file] incoming: {filename} ({meta.get('size', 0)} bytes, "
              f"{total} chunks)")
        os.makedirs(self.download_dir, exist_ok=True)

        # ACK the FILE_INIT and ask for chunk 0.
        send_packet(self.state.tcp_sock, MsgType.FILE_ACK,
                    json_payload({"chunk_id": -1, "ok": True, "want": 0}),
                    self.state.session_id)

        received = 0
        from common.crypto import sha256_file
        with open(dest, "wb") as out:
            while received < total:
                chdr, cpayload = recv_packet(self.state.tcp_sock)
                if chdr["flags"] & Flags.ENCRYPTED:
                    cpayload = self.state.decrypt(cpayload)
                if len(cpayload) < 4:
                    break
                cid = int.from_bytes(cpayload[:4], "big")
                out.write(cpayload[4:])
                received += 1
                # ACK and ask for the next chunk.
                send_packet(self.state.tcp_sock, MsgType.FILE_ACK,
                            json_payload({"chunk_id": cid, "ok": True,
                                          "want": received}),
                            self.state.session_id)
        actual = sha256_file(dest)
        expected = meta.get("sha256")
        ok = (actual == expected) if expected else "?"
        print(f"\n[file] saved to {dest} — SHA-256 match: {ok}")

    # ── Sender methods (called from the CLI thread) ─────────────────────

    def send_broadcast(self, text: str) -> None:
        payload, flags = self.state.encrypt(json_payload({
            "from": self.state.username, "text": text, "ts": now_ts(),
        }))
        send_packet(self.state.tcp_sock, MsgType.MSG_BROADCAST, payload,
                    self.state.session_id, flags)

    def send_unicast(self, to_username: str, text: str) -> None:
        payload, flags = self.state.encrypt(json_payload({
            "from": self.state.username,
            "to": to_username,
            "text": text,
            "ts": now_ts(),
        }))
        send_packet(self.state.tcp_sock, MsgType.MSG_UNICAST, payload,
                    self.state.session_id, flags)

    def send_file_to(self, to_username: str, file_path: str,
                     on_progress=None) -> None:
        """Send a file to another user (Báo cáo §7.2).

        Uses send_file() from common.file_transfer with a crypto context
        derived from the session keys. The recipient's username is
        embedded in every FILE_INIT/FILE_CHUNK envelope as "to".
        """
        # Wrap the FILE_INIT metadata with a "to" field so the server
        # relay knows where to forward. send_file() encrypts + sends
        # FILE_INIT then FILE_CHUNK×N.
        crypto_ctx = {"aes_key": self.state.aes_key,
                      "hmac_key": self.state.hmac_key}

        # Pre-send a tiny envelope marker so the relay can route. The
        # send_file helper does the chunking itself.
        # For simplicity in this lab demo, we attach "to" in a tiny
        # MSG_UNICAST preceding the FILE_INIT (the relay sets "to").
        # See relay.relay_file_chunk which reads "to" from the payload.
        # We therefore piggy-back: the FILE_INIT payload already
        # contains the filename meta; we add "to" via a small wrapper.

        # NOTE: in a production build, FILE_INIT would carry "to" directly;
        # here we keep the lab focused on the chunking + crypto flow.
        from common.file_transfer import file_metadata, iter_chunks
        from common.protocol import CHUNK_SIZE
        meta = file_metadata(file_path)
        meta["to"] = to_username
        total = meta["chunks"]

        # Send FILE_INIT with the recipient name embedded.
        init_payload, init_flags = self.state.encrypt(json_payload(meta))
        send_packet(self.state.tcp_sock, MsgType.FILE_INIT, init_payload,
                    self.state.session_id, init_flags)

        # Wait for the first FILE_ACK from the relayed recipient.
        hdr, payload = recv_packet(self.state.tcp_sock)
        if hdr["flags"] & Flags.ENCRYPTED:
            payload = self.state.decrypt(payload)
        ack = parse_json_payload(payload)
        if not ack.get("ok"):
            print(f"[client] recipient rejected FILE_INIT: {ack}")
            return
        next_chunk = ack.get("want", 0)

        for chunk_id, data in iter_chunks(file_path):
            if chunk_id != next_chunk:
                print(f"[client] chunk mismatch (want {next_chunk}, "
                      f"got {chunk_id}) — aborting")
                return
            chunk_payload = chunk_id.to_bytes(4, "big") + data
            enc, fl = self.state.encrypt(chunk_payload)
            send_packet(self.state.tcp_sock, MsgType.FILE_CHUNK, enc,
                        self.state.session_id, fl)
            if on_progress:
                on_progress(chunk_id + 1, total)
            hdr, payload = recv_packet(self.state.tcp_sock)
            if hdr["flags"] & Flags.ENCRYPTED:
                payload = self.state.decrypt(payload)
            ack = parse_json_payload(payload)
            if not ack.get("ok"):
                print(f"[client] recipient reported error on chunk "
                      f"{chunk_id}: {ack}")
                return
            next_chunk = ack.get("want", chunk_id + 1)
        print(f"[client] file sent: {file_path} ({total} chunks)")
