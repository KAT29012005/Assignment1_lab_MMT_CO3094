

import argparse
import os
import sys
import traceback

sys.path.insert(0, __file__[:__file__.rfind("/client/")] if "/client/" in __file__ else ".")

from client.client import Client
from common.network import DEFAULT_TCP_PORT, DEFAULT_UDP_PORT


HELP_TEXT = """\
Commands:
  /login <username>            Authenticate with the server
  /logout                      Disconnect and exit
  /msg <user> <text>           Send a private message
  /broadcast <text>            Send a message to all connected users
  /file <user> <path>          Send a file (chunked, SHA-256 verified)
  /who                         Show last known active users
  /help                        Show this help
  <plain text>                 Shortcut for /broadcast <plain text>
"""


def progress_bar(done: int, total: int, width: int = 30) -> None:
    pct = done / total if total else 1
    filled = int(width * pct)
    bar = "#" * filled + "." * (width - filled)
    sys.stdout.write(f"\r   [{bar}] {done}/{total} chunks ")
    sys.stdout.flush()
    if done == total:
        sys.stdout.write("\n")


def main():
    parser = argparse.ArgumentParser(description="Collaboration client")
    parser.add_argument("--host", default="127.0.0.1",
                        help="server host (default: 127.0.0.1)")
    parser.add_argument("--tcp-port", type=int, default=DEFAULT_TCP_PORT)
    parser.add_argument("--udp-port", type=int, default=DEFAULT_UDP_PORT)
    parser.add_argument("--download-dir", default="./downloads",
                        help="where received files are saved")
    args = parser.parse_args()

    client = Client(server_host=args.host,
                    tcp_port=args.tcp_port,
                    udp_port=args.udp_port,
                    download_dir=args.download_dir)
    print("Type /help for commands. Lines without '/' are broadcast messages.")
    print()

    try:
        while True:
            try:
                line = input("> ").strip()
            except EOFError:
                break
            if not line:
                continue

            if not line.startswith("/"):
                # Default to broadcast
                if not client.state.tcp_sock:
                    print("[error] not connected — use /login first")
                    continue
                client.send_broadcast(line)
                continue

            parts = line.split(maxsplit=2)
            cmd = parts[0].lower()

            if cmd == "/help":
                print(HELP_TEXT)

            elif cmd == "/login":
                if len(parts) < 2:
                    print("usage: /login <username>")
                    continue
                if client.state.tcp_sock:
                    print("[client] already logged in — /logout first")
                    continue
                ok = client.login(parts[1])
                if not ok:
                    print("[client] login failed")

            elif cmd == "/logout":
                client.logout()
                break

            elif cmd == "/msg":
                if len(parts) < 3:
                    print("usage: /msg <user> <text>")
                    continue
                if not client.state.tcp_sock:
                    print("[error] not connected")
                    continue
                client.send_unicast(parts[1], parts[2])

            elif cmd == "/broadcast":
                if len(parts) < 2:
                    print("usage: /broadcast <text>")
                    continue
                if not client.state.tcp_sock:
                    print("[error] not connected")
                    continue
                client.send_broadcast(parts[1])

            elif cmd == "/file":
                if len(parts) < 3:
                    print("usage: /file <user> <path>")
                    continue
                if not client.state.tcp_sock:
                    print("[error] not connected")
                    continue
                path = parts[2]
                if not os.path.isfile(path):
                    print(f"[error] not a file: {path}")
                    continue
                print(f"[client] sending {path} to {parts[1]} ...")
                client.send_file_to(parts[1], path,
                                    on_progress=progress_bar)

            elif cmd == "/who":
                # The server pushes PRESENCE automatically; we just print
                # a hint. A full /who would query and wait for PRESENCE.
                print("[client] watch the [presence] line above for the "
                      "active users list (auto-pushed by the server).")

            else:
                print(f"unknown command: {cmd}  (try /help)")

    except KeyboardInterrupt:
        print()
    finally:
        if client.state.tcp_sock:
            client.logout()


if __name__ == "__main__":
    main()
