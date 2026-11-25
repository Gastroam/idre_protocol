"""Tests for Task 5: Mutually confirmed IDRE v3 handshake and reflection/substitution rejection."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from core.profile_v3 import (
    ProfileV3,
    ProvisioningBundleV3,
    TranscriptV3,
    canonical_profile,
    compute_vocab_digest_v3,
)
from core.session_v3 import encode_direction_state
from core.vocab_codec import load_vocab
from hive.key_schedule_v3 import (
    KeyScheduleError,
    compute_handshake_confirm,
    establish_confirmed_session,
    initialize_session,
    verify_handshake_confirm,
)


def _setup_bundles(tmp_path: Path):
    vp = tmp_path / "vocab.json"
    vp.write_text(json.dumps(["red", "blue", "green", " "]), encoding="utf-8")
    vocab = load_vocab(str(vp))
    profile = ProfileV3(bundle_id=b"\xaa" * 16, expected_vocab_digest=compute_vocab_digest_v3(vocab))
    net_sec = b"\x11" * 32
    fld_sec = b"\x22" * 32
    bundle_a = ProvisioningBundleV3(profile, net_sec, fld_sec, profile.expected_vocab_digest, "A")
    bundle_b = ProvisioningBundleV3(profile, net_sec, fld_sec, profile.expected_vocab_digest, "B")
    transcript = TranscriptV3(
        profile_bytes=canonical_profile(profile),
        session_id=b"\x33" * 16,
        initiator_id="A",
        responder_id="B",
        initiator_nonce=b"\x44" * 32,
        responder_nonce=b"\x55" * 32,
    )
    return bundle_a, bundle_b, transcript


def test_mutual_handshake_agrees_and_matches_directional_states(tmp_path: Path):
    bundle_a, bundle_b, tr = _setup_bundles(tmp_path)

    cand_a = initialize_session(bundle_a, tr)
    cand_b = initialize_session(bundle_b, tr)
    tag_a = compute_handshake_confirm(bundle_a, cand_a)
    tag_b = compute_handshake_confirm(bundle_b, cand_b)

    assert tag_a != tag_b  # distinct role tags

    sess_a = establish_confirmed_session(bundle_a, tr, peer_confirm_tag=tag_b)
    sess_b = establish_confirmed_session(bundle_b, tr, peer_confirm_tag=tag_a)

    assert encode_direction_state(sess_a.tx) == encode_direction_state(sess_b.rx)
    assert encode_direction_state(sess_a.rx) == encode_direction_state(sess_b.tx)


def test_reflection_and_secret_substitution_rejected_without_session(tmp_path: Path):
    bundle_a, bundle_b, tr = _setup_bundles(tmp_path)

    cand_a = initialize_session(bundle_a, tr)
    tag_a = compute_handshake_confirm(bundle_a, cand_a)

    # Reflecting A's own tag back to A must fail
    assert verify_handshake_confirm(bundle_a, cand_a, tag_a) is False
    with pytest.raises(KeyScheduleError, match="handshake_confirmation_failed"):
        establish_confirmed_session(bundle_a, tr, peer_confirm_tag=tag_a)

    # Wrong field_init_secret fails confirmation
    wrong_field_b = replace(bundle_b, field_init_secret=b"\xff" * 32)
    cand_wrong = initialize_session(wrong_field_b, tr)
    tag_wrong = compute_handshake_confirm(wrong_field_b, cand_wrong)
    with pytest.raises(KeyScheduleError, match="handshake_confirmation_failed"):
        establish_confirmed_session(bundle_a, tr, peer_confirm_tag=tag_wrong)
