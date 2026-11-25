"""Tests for Task 11: Inner-pointer invertibility, collision-freeness, leakage, and wrong-field behavior."""

from __future__ import annotations

import hashlib

import pytest

from benchmarks.v3.pointer_candidates import (
    benchmark_pointer_candidates,
    decode_pointer,
    decode_pointer_prf_tag,
    encode_pointer,
    encode_pointer_prf_tag,
)
from core.field_state_v3 import FieldViewV3


def _view(tag: bytes, age: int = 0) -> FieldViewV3:
    return FieldViewV3(
        profile_digest=b"\xaa" * 32,
        age=age,
        binding_bytes=hashlib.sha256(tag).digest(),
    )


@pytest.mark.parametrize("domain_size", [4, 17, 256, 1024])
def test_feistel_pointer_full_domain_bijection_and_zero_collisions(domain_size: int):
    v = _view(b"field-state-0")
    ctx = b"sess:0:epoch:1:seq:0"
    outputs = set()
    for idx in range(domain_size):
        ptr = encode_pointer(v, idx, ctx, domain_size=domain_size, token_pos=0)
        assert len(ptr) == 4
        assert decode_pointer(v, ptr, ctx, domain_size=domain_size, token_pos=0) == idx
        outputs.add(ptr)
    assert len(outputs) == domain_size  # zero collisions


def test_repeated_token_unlinkability_and_context_reuse_leakage():
    v = _view(b"field-state-1")
    ctx = b"sess:0:epoch:1:seq:1"
    domain = 2048

    # Distinct token_pos hides repeated token equality (not constant; ~uniform across domain)
    ptrs = [encode_pointer(v, 42, ctx, domain_size=domain, token_pos=pos) for pos in range(20)]
    assert len(set(ptrs)) >= 16

    # Context + token_pos reuse deterministically leaks equality (documenting why freshness is mandatory)
    p_a = encode_pointer(v, 42, ctx, domain_size=domain, token_pos=7)
    p_b = encode_pointer(v, 42, ctx, domain_size=domain, token_pos=7)
    assert p_a == p_b


def test_wrong_field_diverges_on_feistel_and_rejects_on_prf_tag():
    v_good = _view(b"field-good", age=1)
    v_drifted = _view(b"field-drifted", age=2)
    ctx = b"sess:0:epoch:1:seq:2"

    # Over 32 tokens in domain 1024, drifted field decodes to wrong indices
    mismatches = 0
    for pos in range(32):
        ptr = encode_pointer(v_good, pos, ctx, domain_size=1024, token_pos=pos)
        dec = decode_pointer(v_drifted, ptr, ctx, domain_size=1024, token_pos=pos)
        if dec != pos:
            mismatches += 1
    assert mismatches >= 30

    # PRF tag directly returns None on drifted field (at O(N) decode cost)
    tag_ptr = encode_pointer_prf_tag(v_good, 3, ctx, token_pos=0)
    assert decode_pointer_prf_tag(v_good, tag_ptr, ctx, domain_size=16, token_pos=0) == 3
    assert decode_pointer_prf_tag(v_drifted, tag_ptr, ctx, domain_size=16, token_pos=0) is None


def test_pointer_candidate_benchmark_runs():
    res = benchmark_pointer_candidates(domain_size=512, n_tokens=50)
    assert res["feistel_collisions"] == 0
    assert res["feistel_field_us_per_token"] > 0
    assert res["feistel_hash_us_per_token"] > 0
    assert res["prf_tag_lookup_us_per_token"] > 0
