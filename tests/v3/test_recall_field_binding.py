"""Tests for Task 9: Observed OP_RECALL_V3 packets require current FieldStateV3 (closing v2 audit bypass)."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from core.codec_v3 import OP_RECALL_V3
from core.field_state_v3 import AcceptedEventV3, advance_field
from core.profile_v3 import (
    ProfileV3,
    ProvisioningBundleV3,
    TranscriptV3,
    canonical_profile,
    compute_vocab_digest_v3,
)
from core.session_v3 import encode_direction_state
from core.vocab_codec import load_vocab
from hive.engine_v3 import (
    EngineError,
    direction_message_context,
    prepare_send,
    validate_ack,
    validate_receive,
)
from hive.key_schedule_v3 import (
    compute_handshake_confirm,
    establish_confirmed_session,
    initialize_session,
)


def _make_adaptive_pair(tmp_path: Path):
    vp = tmp_path / "vocab.json"
    vp.write_text(json.dumps(["red", "blue", "green", " "]), encoding="utf-8")
    vocab = load_vocab(str(vp))
    profile = ProfileV3(
        bundle_id=b"\xcd" * 16,
        expected_vocab_digest=compute_vocab_digest_v3(vocab),
        adaptive_codec_enabled=True,
    )
    net_sec = b"\x11" * 32
    fld_sec = b"\x22" * 32
    ba = ProvisioningBundleV3(profile, net_sec, fld_sec, profile.expected_vocab_digest, "A")
    bb = ProvisioningBundleV3(profile, net_sec, fld_sec, profile.expected_vocab_digest, "B")
    tr = TranscriptV3(
        profile_bytes=canonical_profile(profile),
        session_id=b"\x33" * 16,
        initiator_id="A",
        responder_id="B",
        initiator_nonce=b"\x44" * 32,
        responder_nonce=b"\x55" * 32,
    )
    ca = initialize_session(ba, tr)
    cb = initialize_session(bb, tr)
    sa = establish_confirmed_session(ba, tr, peer_confirm_tag=compute_handshake_confirm(bb, cb))
    sb = establish_confirmed_session(bb, tr, peer_confirm_tag=compute_handshake_confirm(ba, ca))
    return sa, sb, profile, vocab


def test_adaptive_recall_rejects_field_only_drift_and_recovers_on_restore(tmp_path: Path):
    sa, sb, profile, vocab = _make_adaptive_pair(tmp_path)

    # Send "red blue green red blue" 3 times (seq 0, 1, 2) with ACK resolution so
    # proposal on seq=2 promotes the entry into both peers' directional dictionaries.
    phrase = "red blue green red blue"
    for seq in range(3):
        ctx = direction_message_context(sa, direction=sa.tx.direction, epoch=1, seq=seq)
        prep = prepare_send(sa.tx, phrase, ctx, profile=profile, vocab=vocab)
        res = validate_receive(sb.rx, prep.packet_bytes, ctx, profile=profile, vocab=vocab)
        assert res.plaintext == phrase
        sb = sb.with_rx(res.next_state)
        sa = sa.with_tx(
            validate_ack(prep.pending_state, res.ack_packet_bytes, profile=profile, session_id=sa.session_id)
        )

    assert len(sa.tx.dict_state.entries) == 1
    assert sa.tx.dict_state == sb.rx.dict_state

    # Prepare seq=3 -> must emit 17-byte OP_RECALL_V3 (wire packet = 54 hdr + 17 stream + 16 tag = 87 bytes)
    ctx3 = direction_message_context(sa, direction=sa.tx.direction, epoch=1, seq=3)
    prep3 = prepare_send(sa.tx, phrase, ctx3, profile=profile, vocab=vocab)
    assert len(prep3.packet_bytes) == 54 + 17 + 16

    # Field-only drift on receiver rejects the OP_RECALL_V3 packet without mutating state
    drifted_rx = replace(
        sb.rx,
        field=advance_field(sb.rx.field, AcceptedEventV3("data_accepted", seq=999, epoch=1)),
    )
    drifted_snap = encode_direction_state(drifted_rx)
    with pytest.raises(EngineError) as exc_info:
        validate_receive(drifted_rx, prep3.packet_bytes, ctx3, profile=profile, vocab=vocab)
    assert exc_info.value.reason == "field_or_mac_mismatch"
    assert encode_direction_state(drifted_rx) == drifted_snap

    # Restoring exact original field decodes the exact same OP_RECALL_V3 packet
    res3 = validate_receive(sb.rx, prep3.packet_bytes, ctx3, profile=profile, vocab=vocab)
    assert res3.plaintext == phrase
    assert res3.next_state.next_seq == 4
