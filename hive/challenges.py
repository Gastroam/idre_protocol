from __future__ import annotations

import secrets
import threading
from typing import Dict, Optional

from .utils import _now_ms

try:
    from idre_clean.core.session import PendingChallenge
except Exception:  # pragma: no cover - fallback for script-style execution
    from core.session import PendingChallenge


class ChallengeStore:
    """Thread-safe store for pending verify challenges."""

    def __init__(self):
        self._lock = threading.Lock()
        self._pending: Dict[str, PendingChallenge] = {}

    @property
    def pending(self) -> Dict[str, PendingChallenge]:
        return self._pending

    def _cleanup(self, *, now_ms: int) -> None:
        dead = []
        for pid, rec in self._pending.items():
            if bool(rec.used) or int(now_ms) > int(rec.expires_at_ms):
                dead.append(pid)
        for pid in dead:
            self._pending.pop(pid, None)

    def issue(self, peer_id: str, *, ttl_ms: int, max_pending: int) -> PendingChallenge:
        pid = str(peer_id)
        ch = secrets.token_hex(16)
        n_ms = int(_now_ms())
        rec = PendingChallenge(
            challenge=str(ch),
            issued_at_ms=int(n_ms),
            expires_at_ms=int(n_ms) + int(ttl_ms),
            used=False,
        )
        with self._lock:
            self._cleanup(now_ms=n_ms)
            if pid not in self._pending and len(self._pending) >= int(max_pending):
                oldest_pid = None
                oldest_t = None
                for k, v in self._pending.items():
                    t = int(getattr(v, "issued_at_ms", 0))
                    if oldest_t is None or t < int(oldest_t):
                        oldest_t = t
                        oldest_pid = k
                if oldest_pid is not None:
                    self._pending.pop(str(oldest_pid), None)
            self._pending[pid] = rec
        return rec

    def peek_if_valid(self, peer_id: str, challenge: str) -> Optional[PendingChallenge]:
        pid = str(peer_id)
        n_ms = int(_now_ms())
        with self._lock:
            self._cleanup(now_ms=n_ms)
            rec = self._pending.get(pid)
            if rec is None:
                return None
            if bool(rec.used):
                self._pending.pop(pid, None)
                return None
            if int(n_ms) > int(rec.expires_at_ms):
                self._pending.pop(pid, None)
                return None
            if str(challenge) != str(rec.challenge):
                return None
            return rec

    def consume(self, peer_id: str, challenge: str) -> bool:
        pid = str(peer_id)
        n_ms = int(_now_ms())
        with self._lock:
            self._cleanup(now_ms=n_ms)
            rec = self._pending.get(pid)
            if rec is None:
                return False
            if bool(rec.used):
                self._pending.pop(pid, None)
                return False
            if int(n_ms) > int(rec.expires_at_ms):
                self._pending.pop(pid, None)
                return False
            if str(challenge) != str(rec.challenge):
                return False
            rec.used = True
            self._pending.pop(pid, None)
            return True


__all__ = ["ChallengeStore"]
