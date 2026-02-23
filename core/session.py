from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, List, Optional, Set

from .neural_codec import NeuralCodec


class NonceWindow:
    """Simple replay window (set + bounded queue)."""

    def __init__(self, capacity: int = 4096):
        self.capacity = int(capacity)
        self._set: Set[int] = set()
        self._q: Deque[int] = deque()

    def check_and_add(self, nonce: int) -> bool:
        n = int(nonce)
        if n in self._set:
            return False
        self._set.add(n)
        self._q.append(n)
        while len(self._q) > self.capacity:
            old = self._q.popleft()
            self._set.discard(old)
        return True

    def contains(self, nonce: int) -> bool:
        return int(nonce) in self._set

    def __contains__(self, nonce: object) -> bool:
        try:
            return self.contains(int(nonce))  # type: ignore[arg-type]
        except Exception:
            return False


@dataclass
class HiveSession:
    """Manages state for an active connection, including replay protection and codecs."""
    session_id: str
    peer_id: str
    start_time: float
    ttl_s: float = 600.0
    ephemeral_salt: int = 0
    seen: NonceWindow = field(default_factory=NonceWindow)
    chain_hash: bytes = b""  # Epoch Anchor: rolling hash of legitimate history
    prev_chain_hash: bytes = b""  # rollback support
    out_seq: int = 0
    in_seq: int = 0
    codec: Optional[NeuralCodec] = None
    ratchet_key: Optional[int] = None  # Ouroboros: current ratchet key
    last_ratchet_hash: str = ""
    pending_acks: List[bytes] = field(default_factory=list)

    def is_valid(self) -> bool:
        """Checks if the session is still within its TTL."""
        return (time.time() - float(self.start_time)) < float(self.ttl_s)

    def clone(self) -> "HiveSession":
        """Returns a deep copy of the session state, useful for rolling back mutations."""
        import copy
        # Deep copy is essential for mutable structures like codec state, nonces, pending_acks
        return copy.deepcopy(self)


@dataclass
class PendingChallenge:
    """Tracks a challenge string issued to a peer during handshake."""
    challenge: str
    issued_at_ms: int
    expires_at_ms: int
    used: bool = False


__all__ = ["NonceWindow", "HiveSession", "PendingChallenge"]
