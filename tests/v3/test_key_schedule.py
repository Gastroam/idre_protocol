"""Tests for Task 5: Field-dependent HKDF-SHA-256 key schedule and context separation."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from core.field_state_v3 import AcceptedEventV3, advance_field, field_view, initialize_field
from core.profile_v3 import (
    DIR_I2R,
    DIR_R2I,
    MSG_TYPE_ACK,
    MSG_TYPE_DATA,
    PROTOCOL_VERSION_V3,
    ROLE_INITIATOR,
    ROLE_RESPONDER,
    MessageContextV3,
    ProfileV3,
    compute_vocab_digest_v3,
)
from core.vocab_codec import load_vocab
from hive.key_schedule_v3 import KeyScheduleError, advance_chain_secret, derive_message_keys


@pytest.fixture
def schedule_fixture(tmp_path: Path):
    vp = tmp_path / "vocab.json"
    vp.write_text(json.dumps(["red", "blue", "green", " "]), encoding="utf-8")
    vocab = load_vocab(str(vp))
    profile = ProfileV3(bundle_id=b"\x11" * 16, expected_vocab_digest=compute_vocab_digest_v3(vocab))
    state = initialize_field(profile, b"\x22" * 32, b"dir:i2r")
    changed = advance_field(state, AcceptedEventV3("data_accepted", seq=0, epoch=1))
    view = field_view(state, profile)
    changed_view = field_view(changed, profile)
    chain = b"\x33" * 32
    ctx = MessageContextV3(
        protocol_version=PROTOCOL_VERSION_V3,
        bundle_id=profile.bundle_id,
        session_id=b"\x44" * 16,
        role=ROLE_INITIATOR,
        peer_id="node-b",
        direction=DIR_I2R,
        epoch=1,
        seq=0,
        msg_type=MSG_TYPE_DATA,
    )
    return view, changed_view, chain, ctx


def test_current_field_changes_message_keys(schedule_fixture):
    view, changed_view, chain, ctx = schedule_fixture
    good = derive_message_keys(view, chain, ctx)
    other = derive_message_keys(changed_view, chain, ctx)

    assert good.body_key != other.body_key
    assert good.header_key != other.header_key
    assert good.ack_key != other.ack_key
    assert good.route_tag != other.route_tag

    # Purpose separation within same snapshot
    assert good.header_key != good.body_key
    assert good.ack_key != good.body_key
    assert good.header_key != good.ack_key
    assert "redacted" in repr(good)


def test_field_remains_effective_after_chain_evolution(schedule_fixture):
    view, changed_view, chain, ctx = schedule_fixture
    next_chain = advance_chain_secret(chain, view, ctx)
    assert next_chain != chain

    k_same = derive_message_keys(view, next_chain, replace(ctx, seq=1))
    k_diff = derive_message_keys(changed_view, next_chain, replace(ctx, seq=1))
    assert k_same.body_key != k_diff.body_key


def test_every_context_component_separates_keys(schedule_fixture):
    view, _, chain, ctx = schedule_fixture
    base = derive_message_keys(view, chain, ctx)

    variants = [
        replace(ctx, bundle_id=b"\x99" * 16),
        replace(ctx, session_id=b"\x88" * 16),
        replace(ctx, role=ROLE_RESPONDER),
        replace(ctx, peer_id="node-c"),
        replace(ctx, direction=DIR_R2I),
        replace(ctx, epoch=2),
        replace(ctx, seq=1),
        replace(ctx, msg_type=MSG_TYPE_ACK),
    ]
    for v_ctx in variants:
        k = derive_message_keys(view, chain, v_ctx)
        assert k.body_key != base.body_key
        assert k.ack_key != base.ack_key


def test_no_ratchet_only_bypass_allowed(schedule_fixture):
    _, _, chain, ctx = schedule_fixture
    with pytest.raises(KeyScheduleError):
        derive_message_keys(None, chain, ctx)  # type: ignore[arg-type]
