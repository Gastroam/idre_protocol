"""Tests for Task 6: Encrypted headers bound to the exact same pre-message field snapshot."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from core.field_state_v3 import AcceptedEventV3, advance_field
from core.session_v3 import encode_direction_state
from hive.engine_v3 import EngineError, direction_message_context, prepare_send, validate_receive
from tests.v3.test_transactions import _make_confirmed_pair


def test_encrypted_header_succeeds_and_rejects_field_drift_atomically(tmp_path: Path):
    sa, sb, profile, vocab = _make_confirmed_pair(tmp_path, encrypted_headers=True)
    ctx_ab = direction_message_context(sa, direction=sa.tx.direction, epoch=1, seq=0)

    prep = prepare_send(sa.tx, "green red", ctx_ab, profile=profile, vocab=vocab)

    # Field-only drift on receiver must fail at route_tag before body decryption
    drifted_rx = replace(
        sb.rx,
        field=advance_field(sb.rx.field, AcceptedEventV3("data_accepted", seq=0, epoch=1)),
    )
    drifted_before = encode_direction_state(drifted_rx)
    with pytest.raises(EngineError) as exc_info:
        validate_receive(drifted_rx, prep.packet_bytes, ctx_ab, profile=profile, vocab=vocab)
    assert exc_info.value.reason == "invalid_route_tag"
    assert encode_direction_state(drifted_rx) == drifted_before

    # Tampered encrypted inner header byte fails AEAD authentication without mutating state
    tampered = bytearray(prep.packet_bytes)
    tampered[54 + 20] ^= 0x01  # flip bit inside encrypted inner header
    rx_before = encode_direction_state(sb.rx)
    with pytest.raises(EngineError) as exc_info2:
        validate_receive(sb.rx, bytes(tampered), ctx_ab, profile=profile, vocab=vocab)
    assert exc_info2.value.reason == "field_or_mac_mismatch"
    assert encode_direction_state(sb.rx) == rx_before

    # Exact matching field decodes cleanly
    res = validate_receive(sb.rx, prep.packet_bytes, ctx_ab, profile=profile, vocab=vocab)
    assert res.plaintext == "green red"
    assert res.next_state.next_seq == 1
