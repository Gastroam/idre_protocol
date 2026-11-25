"""Task 11 (Laboratory Artifact): Invertible Field-Dependent Inner-Pointer Candidates.

Evaluates P7 (intrinsic inner-pointer dependence when outer AEAD is removed and
the fixed vocabulary is known) under matched entropy and resource budgets:
  1. `FeistelPointerV3`             - 4-round balanced Feistel bijection + cycle-walking,
                                      keyed by current `FieldViewV3.binding_bytes` + context + token_pos.
  2. `KeyedHashPermutationBaseline` - Identical Feistel bijection keyed by a 32B SHA-256 state.
  3. `PrfTagLookupPointer`          - 64-bit truncated HMAC tag (explicitly demonstrates O(N) reverse-map cost).

These are laboratory artifacts for research evaluation, not promoted into `IDRE/3.0`.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import struct
import time
from typing import Dict, Optional, Tuple

from core.field_state_v3 import FieldViewV3


def _feistel_params(domain_size: int) -> Tuple[int, int, int, int]:
    """Return `(half_bits, left_mask, right_mask, total_bits)` for cycle-walking Feistel on `0..domain_size-1`."""
    if domain_size < 2:
        raise ValueError("domain_size must be >= 2")
    total_bits = max(2, (domain_size - 1).bit_length())
    if total_bits % 2 == 1:
        total_bits += 1
    half = total_bits // 2
    mask = (1 << half) - 1
    return half, mask, mask, total_bits


def _feistel_round_fn(key: bytes, context: bytes, round_idx: int, right: int, mask: int) -> int:
    msg = b"IDRE-V3-FPE|" + context + struct.pack(">B I", round_idx, right)
    digest = hmac.new(key, msg, hashlib.sha256).digest()
    val = struct.unpack(">I", digest[:4])[0]
    return val & mask


def _feistel_encrypt_int(key: bytes, context: bytes, x: int, domain_size: int, rounds: int = 4) -> int:
    if not (0 <= x < domain_size):
        raise ValueError(f"index {x} out of domain 0..{domain_size - 1}")
    half, lmask, rmask, _ = _feistel_params(domain_size)
    cur = x
    while True:
        left = (cur >> half) & lmask
        right = cur & rmask
        for r in range(rounds):
            f = _feistel_round_fn(key, context, r, right, lmask)
            left, right = right, left ^ f
        cur = (left << half) | right
        if cur < domain_size:
            return cur


def _feistel_decrypt_int(key: bytes, context: bytes, y: int, domain_size: int, rounds: int = 4) -> int:
    if not (0 <= y < domain_size):
        raise ValueError(f"pointer {y} out of domain 0..{domain_size - 1}")
    half, lmask, rmask, _ = _feistel_params(domain_size)
    cur = y
    while True:
        left = (cur >> half) & lmask
        right = cur & rmask
        for r in range(rounds - 1, -1, -1):
            f = _feistel_round_fn(key, context, r, left, lmask)
            left, right = right ^ f, left
        cur = (left << half) | right
        if cur < domain_size:
            return cur


def encode_pointer(
    state_view: FieldViewV3,
    vocab_index: int,
    context: bytes,
    *,
    domain_size: int,
    token_pos: int,
) -> bytes:
    """Invertible 4-byte field-dependent inner pointer (Candidate A: FeistelPointerV3)."""
    pos_ctx = context + struct.pack(">I", token_pos)
    y = _feistel_encrypt_int(state_view.binding_bytes, pos_ctx, vocab_index, domain_size)
    return struct.pack(">I", y)


def decode_pointer(
    state_view: FieldViewV3,
    pointer: bytes,
    context: bytes,
    *,
    domain_size: int,
    token_pos: int,
) -> Optional[int]:
    """Invert a 4-byte FeistelPointerV3 back to `0..domain_size-1`, or `None` if malformed."""
    if len(pointer) != 4:
        return None
    (y,) = struct.unpack(">I", pointer)
    if y >= domain_size:
        return None
    pos_ctx = context + struct.pack(">I", token_pos)
    return _feistel_decrypt_int(state_view.binding_bytes, pos_ctx, y, domain_size)


def encode_pointer_hash_baseline(
    hash_state_key: bytes,
    vocab_index: int,
    context: bytes,
    *,
    domain_size: int,
    token_pos: int,
) -> bytes:
    """Matched non-neural baseline: identical Feistel bijection keyed by 32B SHA-256 state."""
    pos_ctx = context + struct.pack(">I", token_pos)
    y = _feistel_encrypt_int(hash_state_key, pos_ctx, vocab_index, domain_size)
    return struct.pack(">I", y)


def decode_pointer_hash_baseline(
    hash_state_key: bytes,
    pointer: bytes,
    context: bytes,
    *,
    domain_size: int,
    token_pos: int,
) -> Optional[int]:
    if len(pointer) != 4:
        return None
    (y,) = struct.unpack(">I", pointer)
    if y >= domain_size:
        return None
    pos_ctx = context + struct.pack(">I", token_pos)
    return _feistel_decrypt_int(hash_state_key, pos_ctx, y, domain_size)


def encode_pointer_prf_tag(
    state_view: FieldViewV3,
    vocab_index: int,
    context: bytes,
    *,
    token_pos: int,
) -> bytes:
    """Candidate C: 8-byte truncated HMAC tag (detects wrong key directly, but O(N) decode)."""
    msg = b"IDRE-V3-PRFTAG|" + context + struct.pack(">I I", token_pos, vocab_index)
    return hmac.new(state_view.binding_bytes, msg, hashlib.sha256).digest()[:8]


def decode_pointer_prf_tag(
    state_view: FieldViewV3,
    pointer: bytes,
    context: bytes,
    *,
    domain_size: int,
    token_pos: int,
) -> Optional[int]:
    """O(N) reverse lookup decode for Candidate C (explicitly demonstrates setup/scan cost)."""
    if len(pointer) != 8:
        return None
    for idx in range(domain_size):
        cand = encode_pointer_prf_tag(state_view, idx, context, token_pos=token_pos)
        if hmac.compare_digest(cand, pointer):
            return idx
    return None


def benchmark_pointer_candidates(domain_size: int = 256, n_tokens: int = 200) -> Dict[str, object]:
    """Measure inversion correctness, collisions, and encode/decode cost across candidates."""
    view = FieldViewV3(profile_digest=b"\xaa" * 32, age=5, binding_bytes=hashlib.sha256(b"field").digest())
    hash_key = hashlib.sha256(b"hash-state").digest()
    ctx = b"sess:1:dir:i2r:epoch:1:seq:0"

    # Full-domain bijection check for Feistel
    seen = set()
    for i in range(domain_size):
        p = encode_pointer(view, i, ctx, domain_size=domain_size, token_pos=0)
        assert decode_pointer(view, p, ctx, domain_size=domain_size, token_pos=0) == i
        seen.add(p)
    feistel_collisions = domain_size - len(seen)

    # Timing: Feistel (field-keyed) vs Hash baseline vs PRF tag lookup
    t0 = time.perf_counter_ns()
    for pos in range(n_tokens):
        idx = pos % domain_size
        p = encode_pointer(view, idx, ctx, domain_size=domain_size, token_pos=pos)
        assert decode_pointer(view, p, ctx, domain_size=domain_size, token_pos=pos) == idx
    feistel_us = (time.perf_counter_ns() - t0) / 1000.0 / n_tokens

    t0 = time.perf_counter_ns()
    for pos in range(n_tokens):
        idx = pos % domain_size
        p = encode_pointer_hash_baseline(hash_key, idx, ctx, domain_size=domain_size, token_pos=pos)
        assert decode_pointer_hash_baseline(hash_key, p, ctx, domain_size=domain_size, token_pos=pos) == idx
    hash_us = (time.perf_counter_ns() - t0) / 1000.0 / n_tokens

    t0 = time.perf_counter_ns()
    for pos in range(min(n_tokens, 25)):
        idx = pos % domain_size
        p = encode_pointer_prf_tag(view, idx, ctx, token_pos=pos)
        assert decode_pointer_prf_tag(view, p, ctx, domain_size=domain_size, token_pos=pos) == idx
    prf_us = (time.perf_counter_ns() - t0) / 1000.0 / min(n_tokens, 25)

    return {
        "domain_size": domain_size,
        "feistel_collisions": feistel_collisions,
        "feistel_field_us_per_token": round(feistel_us, 2),
        "feistel_hash_us_per_token": round(hash_us, 2),
        "prf_tag_lookup_us_per_token": round(prf_us, 2),
    }
