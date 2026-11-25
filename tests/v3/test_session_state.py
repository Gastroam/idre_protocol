"""Tests for Task 4: Isolated directional session state and canonical snapshots."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from core.field_state_v3 import AcceptedEventV3, advance_field, encode_field, initialize_field
from core.profile_v3 import DIR_I2R, DIR_R2I, ProfileV3, ProvisioningBundleV3, TranscriptV3, canonical_profile, compute_vocab_digest_v3
from core.session_v3 import (
    AcceptedRecordV3,
    DirectionStateV3,
    PendingSendV3,
    SessionStateError,
    decode_direction_state,
    encode_direction_state,
)
from core.vocab_codec import load_vocab
from hive.key_schedule_v3 import initialize_session


def _make_pair(tmp_path: Path):
    vp = tmp_path / "vocab.json"
    vp.write_text(json.dumps(["red", "blue", "green", " "]), encoding="utf-8")
    vocab = load_vocab(str(vp))
    profile = ProfileV3(bundle_id=b"\x01" * 16, expected_vocab_digest=compute_vocab_digest_v3(vocab))
    net_sec = b"\xaa" * 32
    fld_sec = b"\xbb" * 32
    b_a = ProvisioningBundleV3(profile, net_sec, fld_sec, profile.expected_vocab_digest, "A")
    b_b = ProvisioningBundleV3(profile, net_sec, fld_sec, profile.expected_vocab_digest, "B")
    tr = TranscriptV3(
        profile_bytes=canonical_profile(profile),
        session_id=b"\x10" * 16,
        initiator_id="A",
        responder_id="B",
        initiator_nonce=b"\x20" * 32,
        responder_nonce=b"\x30" * 32,
    )
    return initialize_session(b_a, tr), initialize_session(b_b, tr)


def test_tx_rx_and_unrelated_peer_isolation(tmp_path: Path):
    sess_a, sess_b = _make_pair(tmp_path)

    # Initiator tx (i2r) matches responder rx (i2r) byte-for-byte
    assert encode_direction_state(sess_a.tx) == encode_direction_state(sess_b.rx)
    assert encode_direction_state(sess_a.rx) == encode_direction_state(sess_b.tx)

    # Opposite directions have distinct initial fields and chain secrets
    assert encode_field(sess_a.tx.field) != encode_field(sess_a.rx.field)
    assert sess_a.tx.chain_secret != sess_a.rx.chain_secret
    assert sess_a.tx.dict_key != sess_a.rx.dict_key

    # Advancing tx never touches rx
    rx_before = encode_direction_state(sess_a.rx)
    next_tx_field = advance_field(sess_a.tx.field, AcceptedEventV3("data_accepted", seq=0, epoch=1))
    sess_a2 = sess_a.with_tx(replace(sess_a.tx, field=next_tx_field, next_seq=1))
    assert encode_direction_state(sess_a2.rx) == rx_before
    # Original snapshot is completely untouched (discarding candidate leaves live state equal)
    assert sess_a.tx.next_seq == 0
    assert sess_a.tx.field.age == 0


def test_direction_state_roundtrip_with_pending_and_accepted(tmp_path: Path):
    sess_a, _ = _make_pair(tmp_path)
    cand_field = advance_field(sess_a.tx.field, AcceptedEventV3("data_accepted", seq=0, epoch=1))
    populated = replace(
        sess_a.tx,
        last_accepted=AcceptedRecordV3(
            epoch=1, seq=0, packet_digest=b"\x99" * 32, ack_packet_bytes=b"ACKBYTES"
        ),
        pending_send=PendingSendV3(
            epoch=1,
            seq=1,
            packet_bytes=b"PKTBYTES",
            packet_digest=b"\x88" * 32,
            expected_ack_key=b"\x77" * 32,
            expected_ack_nonce=b"\x66" * 12,
            candidate_field=cand_field,
            candidate_chain_secret=b"\x55" * 32,
            candidate_next_seq=2,
        ),
    )
    raw = encode_direction_state(populated)
    assert decode_direction_state(raw) == populated

    with pytest.raises(SessionStateError):
        decode_direction_state(raw + b"\x00")
    with pytest.raises(SessionStateError):
        decode_direction_state(raw[:-1])
