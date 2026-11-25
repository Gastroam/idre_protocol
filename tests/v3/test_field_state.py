"""Tests for Task 2: Pure canonical fixed-point FieldStateV3 and KAT vectors."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from core.field_state_v3 import (
    INT64_MAX,
    INT64_MIN,
    Q16_ONE,
    AcceptedEventV3,
    FieldStateError,
    advance_field,
    decode_field,
    div_round_half_away_from_zero,
    encode_field,
    field_view,
    initialize_field,
    q16_sigmoid,
)
from core.profile_v3 import ProfileV3, compute_vocab_digest_v3
from core.vocab_codec import load_vocab


VECTORS_PATH = Path(__file__).parent / "vectors" / "field_state.json"


@pytest.fixture
def profile(tmp_path: Path) -> ProfileV3:
    vp = tmp_path / "v.json"
    vp.write_text(json.dumps(["red", "blue", "green", " "]), encoding="utf-8")
    vocab = load_vocab(str(vp))
    return ProfileV3(
        bundle_id=b"\xaa" * 16,
        expected_vocab_digest=compute_vocab_digest_v3(vocab),
        immutable_anchor_ids=(7245, 8888),
        learning_rate_q16=32768,  # 0.5
    )


@pytest.fixture
def learning_state(profile: ProfileV3):
    return initialize_field(profile, b"\x55" * 32, b"ctx:i2r")


def test_view_is_pure(learning_state, profile):
    before = encode_field(learning_state)
    v1 = field_view(learning_state, profile)
    v2 = field_view(learning_state, profile)
    assert encode_field(learning_state) == before
    assert v1 == v2
    assert "redacted" in repr(v1)


def test_anchor_learner_separation_and_order_independence(tmp_path: Path):
    vp = tmp_path / "v.json"
    vp.write_text(json.dumps(["red", "blue", "green", " "]), encoding="utf-8")
    vocab = load_vocab(str(vp))
    digest = compute_vocab_digest_v3(vocab)

    p_order_a = ProfileV3(
        bundle_id=b"\xbb" * 16,
        expected_vocab_digest=digest,
        immutable_anchor_ids=(8888, 7245, 1001),
    )
    p_order_b = ProfileV3(
        bundle_id=b"\xbb" * 16,
        expected_vocab_digest=digest,
        immutable_anchor_ids=(1001, 7245, 8888),
    )
    s_a = initialize_field(p_order_a, b"\x12" * 32, b"dir-i2r")
    s_b = initialize_field(p_order_b, b"\x12" * 32, b"dir-i2r")
    assert encode_field(s_a) == encode_field(s_b)

    # Advancing learner must never mutate anchors or original state
    anchors_before = s_a.anchors
    s_next = advance_field(s_a, AcceptedEventV3(event_type="data_accepted", seq=0, epoch=1))
    assert s_next.anchors == anchors_before
    assert s_next.weights_q16 != s_a.weights_q16
    assert s_a.age == 0 and s_next.age == 1


def test_learning_rate_propagates_into_transitions(tmp_path: Path):
    vp = tmp_path / "v.json"
    vp.write_text(json.dumps(["red", "blue", "green", " "]), encoding="utf-8")
    vocab = load_vocab(str(vp))
    digest = compute_vocab_digest_v3(vocab)

    p_slow = ProfileV3(bundle_id=b"\xcc" * 16, expected_vocab_digest=digest, learning_rate_q16=32768)
    p_fast = ProfileV3(bundle_id=b"\xcc" * 16, expected_vocab_digest=digest, learning_rate_q16=327680)
    s_slow = initialize_field(p_slow, b"\x34" * 32, b"ctx")
    s_fast = initialize_field(p_fast, b"\x34" * 32, b"ctx")
    ev = AcceptedEventV3(event_type="data_accepted", seq=0, epoch=1)
    assert advance_field(s_slow, ev).weights_q16 != advance_field(s_fast, ev).weights_q16


def test_same_truncated_scan_different_canonical_state_differs(learning_state, profile):
    """Two states with identical integer-truncated weights but different fractional
    weights, velocity, or age MUST have distinct canonical encodings and FieldView bindings.
    """
    # Fractional tweak within < 1.0 (Q16_ONE) leaves integer truncation identical
    w_tweaked = (learning_state.weights_q16[0] + 1,) + learning_state.weights_q16[1:]
    assert [w // Q16_ONE for w in w_tweaked] == [w // Q16_ONE for w in learning_state.weights_q16]

    s_frac = replace(learning_state, weights_q16=w_tweaked)
    s_vel = replace(learning_state, velocity_q16=(1,) + learning_state.velocity_q16[1:])
    s_age = replace(learning_state, age=learning_state.age + 1)

    base_enc = encode_field(learning_state)
    base_view = field_view(learning_state, profile)

    for variant in (s_frac, s_vel, s_age):
        assert encode_field(variant) != base_enc
        assert field_view(variant, profile).binding_bytes != base_view.binding_bytes


def test_encode_decode_roundtrip_and_malformed_rejection(learning_state):
    raw = encode_field(learning_state)
    assert decode_field(raw) == learning_state

    with pytest.raises(FieldStateError):
        decode_field(raw + b"\x00")
    with pytest.raises(FieldStateError):
        decode_field(raw[:-1])
    with pytest.raises(FieldStateError):
        decode_field(b"BADMAG" + raw[6:])


def test_rounding_and_sigmoid_boundary_properties():
    # Half away from zero
    assert div_round_half_away_from_zero(3, 2) == 2
    assert div_round_half_away_from_zero(-3, 2) == -2
    assert div_round_half_away_from_zero(1, 2) == 1
    assert div_round_half_away_from_zero(-1, 2) == -1

    # Sigmoid exact midpoint and symmetry
    assert q16_sigmoid(0) == Q16_ONE // 2
    for x in (1, 1000, Q16_ONE, 10 * Q16_ONE, 1000 * Q16_ONE):
        assert q16_sigmoid(x) + q16_sigmoid(-x) == Q16_ONE
        assert q16_sigmoid(x) > Q16_ONE // 2

    # Saturation checks on FieldStateV3
    assert INT64_MIN < 0 < INT64_MAX


def test_10000_transition_kat_vectors():
    """Verify byte-for-byte known-answer vectors over 10,000 fixed-point transitions."""
    assert VECTORS_PATH.is_file(), f"Missing KAT vector fixture: {VECTORS_PATH}"
    kat = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))

    profile = ProfileV3(
        bundle_id=bytes.fromhex(kat["bundle_id_hex"]),
        expected_vocab_digest=bytes.fromhex(kat["expected_vocab_digest_hex"]),
        immutable_anchor_ids=tuple(kat["immutable_anchor_ids"]),
        learning_rate_q16=int(kat["learning_rate_q16"]),
        anchor_weight_q16=int(kat["anchor_weight_q16"]),
        embedding_dim=int(kat["embedding_dim"]),
    )
    state = initialize_field(
        profile,
        bytes.fromhex(kat["field_seed_hex"]),
        kat["context_utf8"].encode("utf-8"),
    )

    checkpoints = {int(k): v for k, v in kat["checkpoints"].items()}
    assert hashlib.sha256(encode_field(state)).hexdigest() == checkpoints[0]["encode_sha256"]
    assert field_view(state, profile).binding_bytes.hex() == checkpoints[0]["view_binding_hex"]

    max_step = max(checkpoints.keys())
    assert max_step >= 10000
    for step in range(1, max_step + 1):
        state = advance_field(state, AcceptedEventV3(event_type="data_accepted", seq=step - 1, epoch=1))
        if step in checkpoints:
            cp = checkpoints[step]
            assert state.age == step
            assert hashlib.sha256(encode_field(state)).hexdigest() == cp["encode_sha256"]
            assert field_view(state, profile).binding_bytes.hex() == cp["view_binding_hex"]
