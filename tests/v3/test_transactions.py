"""Tests for Task 6 (Milestone M1): Field-only drift rejection and atomic MAC-valid invalid content."""

from __future__ import annotations

import json
import struct
from dataclasses import replace
from pathlib import Path

import pytest

from core.codec_v3 import pack_strict_stream_v3
from core.field_state_v3 import AcceptedEventV3, advance_field, field_view
from core.profile_v3 import (
    MSG_TYPE_DATA,
    ProfileV3,
    ProvisioningBundleV3,
    TranscriptV3,
    canonical_profile,
    compute_vocab_digest_v3,
)
from core.session_v3 import encode_direction_state
from core.vocab_codec import encode_text, load_vocab
from hive.crypto_v3 import aead_seal, pack_frame_v3
from hive.engine_v3 import (
    EngineError,
    direction_message_context,
    prepare_send,
    validate_ack,
    validate_receive,
)
from hive.key_schedule_v3 import (
    compute_handshake_confirm,
    derive_message_keys,
    establish_confirmed_session,
    initialize_session,
)


def _make_confirmed_pair(tmp_path: Path, *, encrypted_headers: bool = False):
    vp = tmp_path / "vocab.json"
    vp.write_text(json.dumps(["red", "blue", "green", " "]), encoding="utf-8")
    vocab = load_vocab(str(vp))
    max_pt = 3943 if encrypted_headers else 4023
    profile = ProfileV3(
        bundle_id=b"\xab" * 16,
        expected_vocab_digest=compute_vocab_digest_v3(vocab),
        encrypted_headers=encrypted_headers,
        max_plaintext_bytes=max_pt,
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


def _seal_raw_inner_stream(session_sender, raw_inner: bytes, profile: ProfileV3) -> bytes:
    """Test-only helper that seals arbitrary inner bytes under the genuine AEAD body key."""
    state = session_sender.tx
    ctx = direction_message_context(
        session_sender, direction=state.direction, epoch=state.epoch, seq=state.next_seq
    )
    keys = derive_message_keys(field_view(state.field, profile), state.chain_secret, ctx)
    probe = pack_frame_v3(
        msg_type=MSG_TYPE_DATA,
        flags=0,
        direction=state.direction,
        bundle_id=profile.bundle_id,
        session_id=session_sender.session_id,
        epoch=state.epoch,
        seq=state.next_seq,
        body_bytes=b"\x00" * (len(raw_inner) + 16),
        max_wire_cell_bytes=profile.max_wire_cell_bytes,
    )
    hdr = probe[:54]
    return hdr + aead_seal(keys.body_key, keys.body_nonce, raw_inner, hdr)


def test_g1_field_only_mismatch_rejects_and_restore_recovers(tmp_path: Path):
    sa, sb, profile, vocab = _make_confirmed_pair(tmp_path)

    ctx_ab = direction_message_context(sa, direction=sa.tx.direction, epoch=1, seq=0)
    prep = prepare_send(sa.tx, "red blue", ctx_ab, profile=profile, vocab=vocab)

    # Change ONLY receiver's canonical FieldStateV3 (chain_secret, seq, epoch, vocab unchanged!)
    drifted_field = advance_field(sb.rx.field, AcceptedEventV3("data_accepted", seq=99, epoch=1))
    drifted_rx = replace(sb.rx, field=drifted_field)
    drifted_before = encode_direction_state(drifted_rx)

    with pytest.raises(EngineError) as exc_info:
        validate_receive(drifted_rx, prep.packet_bytes, ctx_ab, profile=profile, vocab=vocab)
    assert exc_info.value.reason == "field_or_mac_mismatch"
    assert "red" not in str(exc_info.value)
    assert encode_direction_state(drifted_rx) == drifted_before

    # Restoring exact original field restores decoding of the exact same packet
    res = validate_receive(sb.rx, prep.packet_bytes, ctx_ab, profile=profile, vocab=vocab)
    assert res.plaintext == "red blue"
    assert res.next_state.field.age == 1
    assert res.next_state.next_seq == 1

    # Sender resolves pending send via authenticated ACK -> states re-converge byte-for-byte
    sa_tx_after = validate_ack(
        prep.pending_state, res.ack_packet_bytes, profile=profile, session_id=sa.session_id
    )
    assert sa_tx_after.field == res.next_state.field
    assert sa_tx_after.chain_secret == res.next_state.chain_secret
    assert sa_tx_after.next_seq == res.next_state.next_seq


def test_mac_valid_invalid_content_preserves_complete_state(tmp_path: Path):
    sa, sb, profile, vocab = _make_confirmed_pair(tmp_path)
    ctx_ab = direction_message_context(sa, direction=sa.tx.direction, epoch=1, seq=0)
    rx_before = encode_direction_state(sb.rx)

    # Create a different vocabulary for wrong_vocab case
    vp2 = tmp_path / "other_vocab.json"
    vp2.write_text(json.dumps(["cyan", "magenta", " "]), encoding="utf-8")
    other_vocab = load_vocab(str(vp2))

    wrong_vocab_blob = encode_text("cyan magenta", other_vocab, allow_literals=False)
    literal_escape_blob = encode_text("red yellow", vocab, allow_literals=True)
    valid_blob = encode_text("red blue", vocab, allow_literals=False)

    cases = [
        ("wrong_vocab", pack_strict_stream_v3(wrong_vocab_blob, max_plaintext_bytes=4023)),
        ("literal_disallowed", pack_strict_stream_v3(literal_escape_blob, max_plaintext_bytes=4023)),
        ("truncated_stream", b"\x00\x00\x10short"),
        ("unsupported_opcode", b"\x7f\x00\x02hi"),
        (
            "trailing_garbage",
            pack_strict_stream_v3(valid_blob, max_plaintext_bytes=4023) + b"\xde\xad",
        ),
        (
            "oversize_payload",
            struct.pack(">B H", 0x00, 4024) + (b"x" * 4024),
        ),
    ]

    for expected_reason, raw_inner in cases:
        if len(raw_inner) + 54 + 16 > profile.max_wire_cell_bytes:
            # Oversize declared length with shorter actual body still tests declared oversize check
            raw_inner = struct.pack(">B H", 0x00, 4024) + b"x"
        pkt = _seal_raw_inner_stream(sa, raw_inner, profile)
        with pytest.raises(EngineError) as exc_info:
            validate_receive(sb.rx, pkt, ctx_ab, profile=profile, vocab=vocab)
        assert exc_info.value.reason == expected_reason
        assert "red" not in str(exc_info.value)
        assert "yellow" not in str(exc_info.value)
        assert encode_direction_state(sb.rx) == rx_before
