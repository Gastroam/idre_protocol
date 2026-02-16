from __future__ import annotations

import hashlib
import hmac
from typing import List


def kdf_int(input_key: int, data: str) -> int:
    """HMAC-SHA256(Key, Data) -> big integer."""
    key_bytes = str(int(input_key)).encode()
    data_bytes = str(data).encode()
    digest = hmac.new(key_bytes, data_bytes, hashlib.sha256).hexdigest()
    return int(digest, 16)


def derive_ratchet_bits(ratchet_key: int, target_len: int) -> List[int]:
    """Expand a ratchet key into a deterministic stream of 0/1 bits."""
    out: List[int] = []
    counter = 0
    key_bytes = str(int(ratchet_key)).encode()

    while len(out) < int(target_len):
        block = hmac.new(key_bytes, int(counter).to_bytes(4, "big"), hashlib.sha256).digest()
        for b in block:
            for i in range(8):
                if len(out) >= int(target_len):
                    break
                out.append((b >> i) & 1)
        counter += 1
    return out


__all__ = ["kdf_int", "derive_ratchet_bits"]

