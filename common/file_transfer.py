
import os
import math
from typing import Optional

from .protocol import (
    CHUNK_SIZE, MsgType, Flags,
    build_packet, send_packet, recv_packet,
    json_payload, parse_json_payload,
)
from .crypto import sha256_file, sha256_bytes


class FileTransferError(Exception):
    """Raised when a file transfer fails (corruption, timeout, abort)."""


# ── Sender side ──────────────────────────────────────────────────────────────

def file_metadata(path: str) -> dict:
    """Build the FILE_INIT metadata dict for a local file."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"not a file: {path}")
    size = os.path.getsize(path)
    chunks = max(1, math.ceil(size / CHUNK_SIZE))
    return {
        "filename": os.path.basename(path),
        "size": size,
        "chunks": chunks,
        "sha256": sha256_file(path),
    }


def iter_chunks(path: str):
    """Yield (chunk_id, chunk_bytes) pairs for a file.

    The last chunk may be shorter than CHUNK_SIZE; that is fine because
    the protocol prepends PAYLOAD_LEN, so the receiver knows the exact
    length of every chunk.
    """
    chunk_id = 0
    with open(path, "rb") as fh:
        while True:
            data = fh.read(CHUNK_SIZE)
            if not data:
                break
            yield chunk_id, data
            chunk_id += 1


def send_file(sock, path: str, session_id: int = 0,
              crypto_ctx=None, on_progress=None) -> None:
    """Send a file over a TCP socket using FILE_INIT + FILE_CHUNK×N.

    Parameters
    ----------
    sock       : connected TCP socket
    path       : local file path to send
    session_id : session ID of the sender (for header)
    crypto_ctx : optional dict {aes_key, hmac_key, ...} — if present,
                 each FILE_CHUNK payload is encrypted before transmission
    on_progress: optional callback(chunk_id, total_chunks) for UI

    Raises FileTransferError if any FILE_ACK reports failure.
    """
    meta = file_metadata(path)
    total = meta["chunks"]

    # 1. Send FILE_INIT — receiver allocates a temp file & replies FILE_ACK(want=0)
    init_payload = json_payload(meta)
    if crypto_ctx:
        from .crypto import encrypt_payload
        init_payload = encrypt_payload(init_payload,
                                      crypto_ctx["aes_key"],
                                      crypto_ctx["hmac_key"])
        send_packet(sock, MsgType.FILE_INIT, init_payload, session_id, Flags.ENCRYPTED)
    else:
        send_packet(sock, MsgType.FILE_INIT, init_payload, session_id)

    # 2. Wait for the first FILE_ACK — receiver tells us which chunk to send.
    hdr, payload = recv_packet(sock)
    if hdr["msg_type"] != MsgType.FILE_ACK:
        raise FileTransferError(
            f"expected FILE_ACK, got msg_type=0x{hdr['msg_type']:02X}")
    ack = parse_json_payload(payload)
    if not ack.get("ok"):
        raise FileTransferError(f"receiver rejected FILE_INIT: {ack}")
    next_chunk = ack.get("want", 0)

    # 3. Stop-and-wait per chunk (rdt3.0 simplified — see Báo cáo §7.2)
    for chunk_id, data in iter_chunks(path):
        if chunk_id != next_chunk:
            # Receiver asked for a chunk we did not expect — abort to avoid
            # corrupting the stream. In a GBN/SR upgrade (Báo cáo §13)
            # we would buffer and reorder instead.
            raise FileTransferError(
                f"chunk mismatch: receiver wanted {next_chunk}, sender at {chunk_id}")

        # Build the chunk payload: 4-byte chunk_id (big-endian) + raw bytes
        chunk_payload = chunk_id.to_bytes(4, "big") + data
        if crypto_ctx:
            from .crypto import encrypt_payload
            chunk_payload = encrypt_payload(chunk_payload,
                                            crypto_ctx["aes_key"],
                                            crypto_ctx["hmac_key"])
            send_packet(sock, MsgType.FILE_CHUNK, chunk_payload,
                        session_id, Flags.ENCRYPTED)
        else:
            send_packet(sock, MsgType.FILE_CHUNK, chunk_payload, session_id)

        if on_progress:
            on_progress(chunk_id + 1, total)

        # 4. Wait for FILE_ACK before sending the next chunk.
        hdr, payload = recv_packet(sock)
        if hdr["msg_type"] != MsgType.FILE_ACK:
            raise FileTransferError(
                f"expected FILE_ACK for chunk {chunk_id}, "
                f"got msg_type=0x{hdr['msg_type']:02X}")
        ack = parse_json_payload(payload)
        if not ack.get("ok"):
            raise FileTransferError(
                f"receiver reported error on chunk {chunk_id}: {ack}")
        next_chunk = ack.get("want", chunk_id + 1)

    # 5. Done. Receiver computes SHA-256 of the reassembled file and
    #    compares with meta["sha256"]; mismatch is reported via ERROR.


# ── Receiver side ────────────────────────────────────────────────────────────

def receive_file(sock, dest_dir: str, session_id: int = 0,
                 crypto_ctx=None, on_progress=None) -> str:
    """Receive a file sent via send_file(). Returns the saved file path.

    Protocol:
      1. Receive FILE_INIT (metadata + sha256)
      2. Allocate dest_path = dest_dir/<filename>
      3. Send FILE_ACK(ok=True, want=0)
      4. Loop: receive FILE_CHUNK, write to disk, send FILE_ACK(want=next)
      5. After the last chunk: recompute SHA-256 and compare with meta.

    Raises FileTransferError if the SHA-256 does not match.
    """
    # 1. Receive FILE_INIT
    hdr, payload = recv_packet(sock)
    if hdr["msg_type"] != MsgType.FILE_INIT:
        raise FileTransferError(
            f"expected FILE_INIT, got msg_type=0x{hdr['msg_type']:02X}")
    if crypto_ctx and (hdr["flags"] & Flags.ENCRYPTED):
        from .crypto import decrypt_payload
        payload = decrypt_payload(payload,
                                  crypto_ctx["aes_key"],
                                  crypto_ctx["hmac_key"])
    meta = parse_json_payload(payload)
    expected_sha = meta.get("sha256")
    total = meta.get("chunks", 0)

    # 2. Allocate destination path (avoid path traversal)
    filename = os.path.basename(meta["filename"])
    dest_path = os.path.join(dest_dir, filename)
    os.makedirs(dest_dir, exist_ok=True)

    # 3. ACK the FILE_INIT — tell sender we want chunk 0.
    send_packet(sock, MsgType.FILE_ACK,
                json_payload({"chunk_id": -1, "ok": True, "want": 0}),
                session_id)

    # 4. Stop-and-wait receive loop
    received = 0
    with open(dest_path, "wb") as out:
        while received < total:
            hdr, payload = recv_packet(sock)
            if hdr["msg_type"] != MsgType.FILE_CHUNK:
                raise FileTransferError(
                    f"expected FILE_CHUNK #{received}, "
                    f"got msg_type=0x{hdr['msg_type']:02X}")
            if crypto_ctx and (hdr["flags"] & Flags.ENCRYPTED):
                from .crypto import decrypt_payload
                payload = decrypt_payload(payload,
                                          crypto_ctx["aes_key"],
                                          crypto_ctx["hmac_key"])
            if len(payload) < 4:
                raise FileTransferError("chunk payload too short for chunk_id")
            chunk_id = int.from_bytes(payload[:4], "big")
            data = payload[4:]
            if chunk_id != received:
                raise FileTransferError(
                    f"out-of-order chunk: wanted {received}, got {chunk_id}")
            out.write(data)
            received += 1
            if on_progress:
                on_progress(received, total)
            # ACK this chunk and ask for the next one.
            send_packet(sock, MsgType.FILE_ACK,
                        json_payload({"chunk_id": chunk_id, "ok": True,
                                      "want": received}),
                        session_id)

    # 5. Verify end-to-end integrity (Báo cáo §8.3).
    actual_sha = sha256_file(dest_path)
    if expected_sha and actual_sha != expected_sha:
        os.remove(dest_path)
        raise FileTransferError(
            f"SHA-256 mismatch: expected {expected_sha}, got {actual_sha}")
    return dest_path
