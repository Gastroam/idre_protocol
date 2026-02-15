from dataclasses import dataclass, field
from typing import List, Optional
import time
from idre_clean.core.neural_codec import NeuralCodec

class NonceWindow:
    def __init__(self, capacity: int = 4096):
        self.capacity = int(capacity)
        self._set = set()
        self._queue: List[int] = []

    def check_and_add(self, nonce: int) -> bool:
        n = int(nonce)
        if n in self._set:
            return False
        self._set.add(n)
        self._queue.append(n)
        if len(self._queue) > self.capacity:
            old = self._queue.pop(0)
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
    chain_hash: bytes = b"" # Epoch Anchor: Rolling hash of legitimate history
    prev_chain_hash: bytes = b"" # Previous hash state (for rollback on delivery failure)
    out_seq: int = 0
    in_seq: int = 0
    codec: Optional[NeuralCodec] = None
    ratchet_key: Optional[int] = None # Ouroboros: Current "Private Physics" derived from Reality
    last_ratchet_hash: str = ""
    pending_acks: List[bytes] = field(default_factory=list)

    def is_valid(self) -> bool:
        return (time.time() - float(self.start_time)) < float(self.ttl_s)

@dataclass
class PendingChallenge:
    challenge: str
    issued_at_ms: int
    expires_at_ms: int
    used: bool = False
