from __future__ import annotations

import hashlib
from typing import List, Tuple


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _expand_bytes(seed: bytes, n: int, domain: bytes) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        out.extend(_sha256(domain + seed + counter.to_bytes(4, "big")))
        counter += 1
    return bytes(out[:n])


def compute_block_salt(bits: List[int], session_id: str, block_index: int) -> bytes:
    bitstring = "".join(str(int(b) & 1) for b in bits)
    raw = f"{bitstring}:{session_id}:{int(block_index)}".encode("utf-8")
    return _sha256(raw)


def derive_keystream_and_permutation(salt: bytes, block_len: int) -> Tuple[List[int], List[int]]:
    """Derive (keystream bytes, permutation indices) from a per-block salt."""
    block_len = int(block_len)
    ks = _expand_bytes(salt, block_len, b"K/")
    k_t = [b for b in ks]

    ranks = []
    for i in range(block_len):
        r = _sha256(b"P/" + salt + i.to_bytes(2, "big"))
        ranks.append((r, i))
    ranks.sort(key=lambda x: x[0])
    pi_t = [i for _r, i in ranks]

    return k_t, pi_t


def permute(block: List[int], pi_t: List[int]) -> List[int]:
    return [int(block[i]) & 0xFF for i in pi_t]


def inverse_permute(block: List[int], pi_t: List[int]) -> List[int]:
    out = [0] * len(pi_t)
    for i, target in enumerate(pi_t):
        out[int(target)] = int(block[i]) & 0xFF
    return out


def xor_bytes(a: List[int], b: List[int]) -> List[int]:
    return [(int(x) ^ int(y)) & 0xFF for x, y in zip(a, b)]

