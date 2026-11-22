
import os
import sys
import time
import socket
import tempfile
import threading

# Allow running from anywhere under Assignment1_Lab_MMT/
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from server.server import Server
from client.client import Client


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def main():
    # 1. Start the server
    tcp_port = _free_port()
    udp_port = _free_port()
    server = Server(host="127.0.0.1", tcp_port=tcp_port, udp_port=udp_port)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.5)

    # 2. Create a 50 MB random file (test payload)
    file_size = 50 * 1024 * 1024     # 50 MB
    src_dir = tempfile.mkdtemp(prefix="demo_src_")
    dst_dir = tempfile.mkdtemp(prefix="demo_dst_")
    src_path = os.path.join(src_dir, "demo_file.bin")
    print(f"[demo] generating {file_size // (1024*1024)} MB random file...")
    with open(src_path, "wb") as fh:
        # Write in chunks to avoid holding 50 MB in RAM
        remaining = file_size
        chunk = 1024 * 1024
        while remaining > 0:
            n = min(chunk, remaining)
            fh.write(os.urandom(n))
            remaining -= n
    print(f"[demo] file ready: {src_path} ({os.path.getsize(src_path)} bytes)")

    # 3. Login both clients
    alice = Client(server_host="127.0.0.1", tcp_port=tcp_port,
                   udp_port=udp_port, download_dir=dst_dir)
    bob = Client(server_host="127.0.0.1", tcp_port=tcp_port,
                 udp_port=udp_port, download_dir=dst_dir)
    assert alice.login("alice"), "Alice login failed"
    assert bob.login("bob"), "Bob login failed"
    time.sleep(0.3)   # let PRESENCE propagate

    # 4. Send the file and measure throughput
    print("[demo] Alice -> sending 50 MB to Bob ...")
    start = time.perf_counter()
    alice.send_file_to("bob", src_path)
    # Bob's receiver thread writes the file; we poll for completion.
    expected_name = os.path.basename(src_path)
    dst_path = os.path.join(dst_dir, expected_name)
    while not os.path.exists(dst_path):
        time.sleep(0.1)
    # Give the receiver thread a moment to finish the last write + SHA verify
    time.sleep(0.5)
    elapsed = time.perf_counter() - start
    throughput = file_size / elapsed / (1024 * 1024)

    print(f"[demo] transfer complete in {elapsed:.2f} s")
    print(f"[demo] throughput: {throughput:.2f} MB/s")

    # 5. Verify SHA-256
    import hashlib
    def sha256(p):
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            while True:
                b = fh.read(65536)
                if not b:
                    break
                h.update(b)
        return h.hexdigest()
    src_sha = sha256(src_path)
    dst_sha = sha256(dst_path)
    print(f"[demo] src SHA-256: {src_sha}")
    print(f"[demo] dst SHA-256: {dst_sha}")
    print(f"[demo] SHA-256 match: {src_sha == dst_sha}")

    # 6. Cleanup
    alice.logout()
    bob.logout()
    server._shutdown.set()
    time.sleep(0.2)

    if src_sha == dst_sha:
        print("\n✓ Demo PASSED — file transferred without bit errors.")
        return 0
    else:
        print("\n✗ Demo FAILED — SHA-256 mismatch.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
