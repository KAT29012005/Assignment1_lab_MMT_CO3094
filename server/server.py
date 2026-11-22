

import argparse
import secrets
import socket
import sys
import threading
import time
import traceback

# Allow `python -m server.server` from the repo root
sys.path.insert(0, __file__[:__file__.rfind("/server/")] if "/server/" in __file__ else ".")

from common.protocol import (
    MsgType, Flags, build_packet, send_packet, recv_packet,
    json_payload, parse_json_payload, now_ts, HEADER_SIZE, parse_header,
)
from common.crypto import (
    generate_rsa_keypair, serialize_public_key, load_public_key,
    generate_session_keys, encrypt_session_keys_for_client,
)
from common.network import (
    DEFAULT_TCP_PORT, DEFAULT_UDP_PORT,
    make_tcp_server_socket, make_udp_socket, safe_sendall,
)
from server.user_manager import UserManager, UserSession
from server.relay import (
    relay_unicast, relay_broadcast, relay_file_chunk,
    send_presence, send_error,
)


class Server:
    """The collaboration server.

    Holds long-lived state:
      - RSA keypair (long-term, used to sign AUTH_ACK)
      - UserManager (active sessions)
      - shutdown flag (graceful stop)
    """

    HEARTBEAT_TTL = 60.0       # seconds without heartbeat = stale
    CLEANUP_INTERVAL = 15.0    # cleanup thread runs every 15 s

    def __init__(self, host: str = "0.0.0.0",
                 tcp_port: int = DEFAULT_TCP_PORT,
                 udp_port: int = DEFAULT_UDP_PORT):
        self.host = host
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.users = UserManager()
        self._next_session_id = 1000
        self._session_id_lock = threading.Lock()
        self._shutdown = threading.Event()

        # Long-term RSA keypair for the server (Báo cáo §8.1)
        print("[server] generating RSA-2048 keypair (this may take a second)...")
        self._rsa_priv, self._rsa_pub = generate_rsa_keypair()
        print("[server] RSA-2048 keypair ready.")

    # ── Session ID allocation ──────────────────────────────────────────────

    def _allocate_session_id(self) -> int:
        with self._session_id_lock:
            self._next_session_id += 1
            return self._next_session_id

    # ── AUTH handler ───────────────────────────────────────────────────────

    def _handle_auth(self, sock, payload: bytes) -> UserSession:
        """Process an AUTH packet; return the new UserSession or raise."""
        req = parse_json_payload(payload)
        username = req.get("username", "").strip()
        if not username or len(username) > 32:
            raise ValueError("invalid username")
        client_pubkey_pem = req.get("pubkey_pem", "").encode("utf-8")
        if not client_pubkey_pem:
            raise ValueError("missing client public key")

        client_pubkey = load_public_key(client_pubkey_pem)
        session_id = self._allocate_session_id()

        # Generate per-session AES + HMAC keys (Báo cáo §8.1)
        aes_key, hmac_key = generate_session_keys()
        encrypted_keys = encrypt_session_keys_for_client(
            aes_key, hmac_key, client_pubkey)

        # Build AUTH_ACK payload
        ack = {
            "session_id": session_id,
            "server_pubkey_pem": serialize_public_key(self._rsa_pub).decode("utf-8"),
            "encrypted_session_keys_b64": encrypted_keys.hex(),  # hex for JSON
        }
        send_packet(sock, MsgType.AUTH_ACK, json_payload(ack), session_id)

        # Register the session
        session = UserSession(
            session_id=session_id,
            username=username,
            tcp_sock=sock,
            pubkey=client_pubkey_pem,
            aes_key=aes_key,
            hmac_key=hmac_key,
        )
        self.users.add(session)
        print(f"[server] AUTH ok: {username} (session_id={session_id})")
        return session

    # ── Per-client TCP handler thread ─────────────────────────────────────

    def _handle_client(self, sock: socket.socket, addr) -> None:
        """Thread body for one TCP client (Báo cáo §4.2, §9)."""
        session: UserSession | None = None
        sock.settimeout(30)   # AUTH_TIMEOUT plus margin
        try:
            # 1. Block on the AUTH packet
            hdr, payload = recv_packet(sock)
            if hdr["msg_type"] != MsgType.AUTH:
                send_error(sock, 0, 400, "expected AUTH first")
                return
            session = self._handle_auth(sock, payload)
            sock.settimeout(None)       # rely on SO_RCVTIMEO for the rest

            # 2. Announce to everyone
            send_presence(self.users)

            # 3. Main receive loop
            while not self._shutdown.is_set():
                hdr, payload = recv_packet(sock)
                self.users.touch(session.session_id)

                if hdr["msg_type"] == MsgType.MSG_BROADCAST:
                    recipients = self.users.snapshot_for_broadcast()
                    relay_broadcast(session, recipients, payload)

                elif hdr["msg_type"] == MsgType.MSG_UNICAST:
                    plain = _decrypt_if_needed(payload, session)
                    env = parse_json_payload(plain)
                    target_name = env.get("to")
                    recipient = self.users.get_by_username(target_name)
                    if recipient is None:
                        send_error(sock, session.session_id, 404,
                                   f"recipient '{target_name}' not online",
                                   recipient=session)
                        continue
                    relay_unicast(sock, session, recipient, hdr, payload)

                elif hdr["msg_type"] in (MsgType.FILE_INIT, MsgType.FILE_CHUNK,
                                         MsgType.FILE_ACK):
                    plain = _decrypt_if_needed(payload, session)
                    env = parse_json_payload(plain) if plain else {}
                    target_name = env.get("to")
                    recipient = self.users.get_by_username(target_name) if target_name else None
                    if recipient is None:
                        send_error(sock, session.session_id, 404,
                                   f"file recipient '{target_name}' not online",
                                   recipient=session)
                        continue
                    relay_file_chunk(session, recipient, payload, hdr["flags"])

                else:
                    send_error(sock, session.session_id, 400,
                               f"unexpected msg_type 0x{hdr['msg_type']:02X}",
                               recipient=session)

        except (ConnectionError, socket.timeout, OSError) as exc:
            print(f"[server] client {addr} disconnected: {exc}")
        except Exception as exc:                       # noqa: BLE001
            print(f"[server] handler error for {addr}: {exc}")
            traceback.print_exc()
            try:
                send_error(sock, 0, 500, str(exc))
            except Exception:
                pass
        finally:
            if session:
                self.users.remove(session.session_id)
                send_presence(self.users)
            try:
                sock.close()
            except OSError:
                pass

    # ── UDP heartbeat listener ───────────────────────────────────────────

    def _handle_udp(self, udp_sock: socket.socket) -> None:
        """Listen for HEARTBEAT packets on UDP (Báo cáo §4.1, §11.4)."""
        udp_sock.settimeout(5)
        while not self._shutdown.is_set():
            try:
                data, addr = udp_sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                if len(data) < HEADER_SIZE:
                    continue
                hdr = parse_header(data[:HEADER_SIZE])
                if hdr["msg_type"] != MsgType.HEARTBEAT:
                    continue
                # Touch the session — heartbeat proves the client is alive
                self.users.touch(hdr["session_id"])
            except Exception as exc:    # noqa: BLE001
                print(f"[server] UDP heartbeat error from {addr}: {exc}")

    # ── Cleanup thread ──────────────────────────────────────────────────

    def _cleanup_loop(self) -> None:
        """Reap stale sessions (Báo cáo §9, §11.2)."""
        while not self._shutdown.is_set():
            time.sleep(self.CLEANUP_INTERVAL)
            stale = self.users.reap_stale(self.HEARTBEAT_TTL)
            for sid in stale:
                print(f"[server] reaping stale session_id={sid}")
                send_presence(self.users)

    # ── Main loop ───────────────────────────────────────────────────────

    def serve_forever(self) -> None:
        tcp_sock = make_tcp_server_socket(self.host, self.tcp_port)
        udp_sock = make_udp_socket((self.host, self.udp_port))

        # Start UDP listener
        threading.Thread(target=self._handle_udp, args=(udp_sock,),
                         daemon=True, name="udp-listener").start()
        # Start cleanup loop
        threading.Thread(target=self._cleanup_loop, daemon=True,
                         name="cleanup").start()

        print(f"[server] listening on TCP {self.host}:{self.tcp_port} "
              f"+ UDP {self.host}:{self.udp_port}")
        try:
            while not self._shutdown.is_set():
                try:
                    client_sock, client_addr = tcp_sock.accept()
                except OSError:
                    break
                print(f"[server] accepted connection from {client_addr}")
                threading.Thread(target=self._handle_client,
                                 args=(client_sock, client_addr),
                                 daemon=True).start()
        except KeyboardInterrupt:
            print("\n[server] shutting down (Ctrl-C)")
        finally:
            self._shutdown.set()
            try:
                tcp_sock.close()
                udp_sock.close()
            except OSError:
                pass


# ── Helper used in both the handler and relay ─────────────────────────────

def _decrypt_if_needed(payload: bytes, session: UserSession) -> bytes:
    if session.aes_key and session.hmac_key:
        from common.crypto import decrypt_payload
        return decrypt_payload(payload, session.aes_key, session.hmac_key)
    return payload


# ── CLI entry point ────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Collaboration server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--tcp-port", type=int, default=DEFAULT_TCP_PORT)
    parser.add_argument("--udp-port", type=int, default=DEFAULT_UDP_PORT)
    args = parser.parse_args()
    server = Server(args.host, args.tcp_port, args.udp_port)
    server.serve_forever()


if __name__ == "__main__":
    main()
