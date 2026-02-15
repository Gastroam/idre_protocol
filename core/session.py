from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Set


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


@dataclass
class HiveSession:
    session_id: str
    peer_id: str
    start_time: float
    ttl_s: float = 600.0
    ephemeral_salt: int = 0
    seen: NonceWindow = field(default_factory=NonceWindow)

    def is_valid(self) -> bool:
        return (time.time() - float(self.start_time)) < float(self.ttl_s)
