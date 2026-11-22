

from typing import Optional

from common.protocol import (
    MsgType, Flags, build_packet, send_packet, recv_packet,
    json_payload, parse_json_payload, now_ts,
)
from common.crypto import encrypt_payload, decrypt_payload
from common.network import safe_sendall
from server.user_manager import UserSession


class RelayError(Exception):
    pass


def _decrypt_if_needed(payload: bytes, session: UserSession) -> bytes:
    """Decrypt payload with the sender's session keys (link encryption)."""
    if session.aes_key and session.hmac_key:
        return decrypt_payload(payload, session.aes_key, session.hmac_key)
    return payload


def _encrypt_for_recipient(payload: bytes,
                           recipient: UserSession) -> tuple:
    """Re-encrypt payload for the recipient, return (payload, flags)."""
    if recipient.aes_key and recipient.hmac_key:
        return (encrypt_payload(payload, recipient.aes_key, recipient.hmac_key),
                Flags.ENCRYPTED)
    return payload, 0


def relay_unicast(sock, sender: UserSession, recipient: UserSession,
                  header: dict, payload: bytes) -> bool:
    """Forward a MSG_UNICAST from sender to recipient.

    Returns True if the recipient's TCP socket accepted the bytes, False
    if it dropped (the caller will then clean up the dead session).
    """
    # 1. Decrypt with sender's K_S (link encryption)
    plaintext = _decrypt_if_needed(payload, sender)

    # 2. Rewrite envelope: set "from" = sender.username
    envelope = parse_json_payload(plaintext)
    envelope["from"] = sender.username
    envelope["ts"] = now_ts()
    new_plaintext = json_payload(envelope)

    # 3. Re-encrypt with recipient's K_S
    new_payload, flags = _encrypt_for_recipient(new_plaintext, recipient)

    # 4. Forward — safe_sendall catches BrokenPipeError per-recipient
    #    so one dead peer does not abort the loop (Báo cáo §11.3).
    packet = build_packet(MsgType.MSG_UNICAST, new_payload,
                          session_id=recipient.session_id, flags=flags)
    return safe_sendall(recipient.tcp_sock, packet)


def relay_broadcast(sender: UserSession, recipients: list,
                    payload: bytes) -> int:
    """Send a MSG_BROADCAST from sender to every recipient.

    Returns the number of recipients that received the bytes. Dead
    recipients are silently skipped (safe_sendall returns False).
    """
    # 1. Decrypt once with sender's K_S — we will re-encrypt per recipient.
    plaintext = _decrypt_if_needed(payload, sender)
    envelope = parse_json_payload(plaintext)
    envelope["from"] = sender.username
    envelope["ts"] = now_ts()
    new_plaintext = json_payload(envelope)

    delivered = 0
    for recipient in recipients:
        if recipient.session_id == sender.session_id:
            continue                          # do not echo to sender
        new_payload, flags = _encrypt_for_recipient(new_plaintext, recipient)
        packet = build_packet(MsgType.MSG_BROADCAST, new_payload,
                              session_id=recipient.session_id, flags=flags)
        if safe_sendall(recipient.tcp_sock, packet):
            delivered += 1
    return delivered


def relay_file_chunk(sender: UserSession, recipient: UserSession,
                     payload: bytes, flags: int) -> bool:
    """Forward a FILE_CHUNK / FILE_INIT / FILE_ACK between two clients.

    File chunks are already encrypted by the sender with the recipient's
    K_S if the sender knows it (peer-key exchange done in MSG_UNICAST
    bootstrap). For the simplified link-encryption model here we
    re-encrypt per recipient.
    """
    # Decrypt with sender's K_S, then re-encrypt for recipient.
    plaintext = _decrypt_if_needed(payload, sender)
    new_payload, new_flags = _encrypt_for_recipient(plaintext, recipient)
    packet = build_packet(MsgType.FILE_CHUNK, new_payload,
                          session_id=recipient.session_id, flags=new_flags)
    return safe_sendall(recipient.tcp_sock, packet)


def send_presence(user_manager, exclude_session: Optional[int] = None) -> None:
    """Broadcast the active-user list to every connected client.

    Called whenever a user joins or leaves. Builds a snapshot under the
    user_manager lock, then iterates WITHOUT the lock and sends —
    see Báo cáo §11.2 (never hold the lock while doing I/O).
    """
    active = user_manager.list_active()
    if exclude_session is not None:
        active = [u for u in active if u["session_id"] != exclude_session]
    payload = json_payload({"users": active})

    sessions = user_manager.snapshot_for_broadcast()
    for s in sessions:
        if s.session_id == exclude_session:
            continue
        new_payload, flags = _encrypt_for_recipient(payload, s)
        packet = build_packet(MsgType.PRESENCE, new_payload,
                              session_id=s.session_id, flags=flags)
        safe_sendall(s.tcp_sock, packet)


def send_error(sock, session_id: int, code: int, message: str,
               recipient: Optional[UserSession] = None) -> None:
    """Send an ERROR packet to a client."""
    payload = json_payload({"code": code, "message": message})
    flags = 0
    if recipient and recipient.aes_key and recipient.hmac_key:
        payload, flags = _encrypt_for_recipient(payload, recipient)
    safe_sendall(sock, build_packet(MsgType.ERROR, payload, session_id, flags))
