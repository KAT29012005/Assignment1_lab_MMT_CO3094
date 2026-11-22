
import threading
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, List


@dataclass
class UserSession:
    """Per-client state held by the server."""
    session_id: int
    username: str
    tcp_sock: object            # socket.socket
    udp_addr: Optional[tuple] = None
    pubkey: Optional[bytes] = None
    aes_key: Optional[bytes] = None
    hmac_key: Optional[bytes] = None
    last_seen: float = field(default_factory=time.time)

    def touch(self) -> None:
        self.last_seen = time.time()


class UserManager:
    """Thread-safe active-user table.

    The server's main loop calls add() in the AUTH handler thread, and
    calls remove() / list_active() from many places concurrently. We
    guard everything with a single lock — short critical sections only,
    NEVER holding the lock while doing socket I/O (Báo cáo §11.2).
    """

    LOCK_TIMEOUT = 2.0       # seconds — see Báo cáo §11.2

    def __init__(self):
        self._sessions: Dict[int, UserSession] = {}
        self._lock = threading.Lock()

    # ── Mutators ───────────────────────────────────────────────────────────

    def add(self, session: UserSession) -> bool:
        if not self._lock.acquire(timeout=self.LOCK_TIMEOUT):
            return False
        try:
            self._sessions[session.session_id] = session
            return True
        finally:
            self._lock.release()

    def remove(self, session_id: int) -> Optional[UserSession]:
        """Atomically remove and return the session, or None if not found."""
        if not self._lock.acquire(timeout=self.LOCK_TIMEOUT):
            return None
        try:
            return self._sessions.pop(session_id, None)
        finally:
            self._lock.release()

    def touch(self, session_id: int) -> bool:
        """Update last_seen on every heartbeat / message from this client."""
        if not self._lock.acquire(timeout=self.LOCK_TIMEOUT):
            return False
        try:
            s = self._sessions.get(session_id)
            if s is None:
                return False
            s.touch()
            return True
        finally:
            self._lock.release()

    # ── Read-only accessors (return copies — caller must not hold the lock
    #    while doing I/O, so we snapshot and release immediately) ──────────

    def get(self, session_id: int) -> Optional[UserSession]:
        if not self._lock.acquire(timeout=self.LOCK_TIMEOUT):
            return None
        try:
            return self._sessions.get(session_id)
        finally:
            self._lock.release()

    def get_by_username(self, username: str) -> Optional[UserSession]:
        if not self._lock.acquire(timeout=self.LOCK_TIMEOUT):
            return None
        try:
            for s in self._sessions.values():
                if s.username == username:
                    return s
            return None
        finally:
            self._lock.release()

    def list_active(self) -> List[dict]:
        """Snapshot of the user table for PRESENCE broadcasts.

        Returns a list of {session_id, username} dicts. We do NOT return
        sockets or keys — callers must look them up again with get()
        to avoid using stale references after a client disconnects.
        """
        if not self._lock.acquire(timeout=self.LOCK_TIMEOUT):
            return []
        try:
            return [{"session_id": s.session_id, "username": s.username}
                    for s in self._sessions.values()]
        finally:
            self._lock.release()

    def snapshot_for_broadcast(self) -> List[UserSession]:
        """Snapshot list of UserSession objects, for message broadcast.

        See Báo cáo §11.2: we acquire the lock only to snapshot, then
        release before iterating + sending, so a slow / dead client
        cannot block other clients.
        """
        if not self._lock.acquire(timeout=self.LOCK_TIMEOUT):
            return []
        try:
            return list(self._sessions.values())
        finally:
            self._lock.release()

    # ── Background janitor ─────────────────────────────────────────────────

    def reap_stale(self, max_age_seconds: float = 60.0) -> List[int]:
        """Remove sessions whose last_seen is older than max_age_seconds.

        Called periodically by the cleanup thread (Báo cáo §9, §11.2).
        Returns the list of removed session_ids so the caller can close
        the TCP sockets.
        """
        if not self._lock.acquire(timeout=self.LOCK_TIMEOUT):
            return []
        try:
            now = time.time()
            stale = [sid for sid, s in self._sessions.items()
                     if now - s.last_seen > max_age_seconds]
            for sid in stale:
                self._sessions.pop(sid, None)
            return stale
        finally:
            self._lock.release()
