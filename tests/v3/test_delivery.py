"""Tests for Task 7: Stop-and-wait delivery, exact retransmission, idempotent ACKs, and crossed sends."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.session_v3 import encode_direction_state
from hive.engine_v3 import (
    EngineError,
    direction_message_context,
    prepare_send,
    validate_ack,
    validate_receive,
)
from tests.v3.test_transactions import _make_confirmed_pair


def test_lost_data_and_exact_byte_retransmission(tmp_path: Path):
    sa, sb, profile, vocab = _make_confirmed_pair(tmp_path)
    ctx0 = direction_message_context(sa, direction=sa.tx.direction, epoch=1, seq=0)

    prep = prepare_send(sa.tx, "red blue", ctx0, profile=profile, vocab=vocab)
    sa_tx_pending = prep.pending_state

    # Cannot send a second DATA packet while seq=0 is pending
    ctx1 = direction_message_context(sa, direction=sa.tx.direction, epoch=1, seq=1)
    with pytest.raises(EngineError) as exc_info:
        prepare_send(sa_tx_pending, "green red", ctx1, profile=profile, vocab=vocab)
    assert exc_info.value.reason == "pending_in_flight"

    # Simulate lost DATA -> retransmit exact stored bytes from pending_send
    assert sa_tx_pending.pending_send is not None
    retry_bytes = sa_tx_pending.pending_send.packet_bytes
    assert retry_bytes == prep.packet_bytes

    res = validate_receive(sb.rx, retry_bytes, ctx0, profile=profile, vocab=vocab)
    assert res.plaintext == "red blue"
    assert res.is_duplicate is False

    sa_tx_done = validate_ack(
        sa_tx_pending, res.ack_packet_bytes, profile=profile, session_id=sa.session_id
    )
    assert sa_tx_done.pending_send is None
    assert sa_tx_done.next_seq == 1
    assert sa_tx_done.field == res.next_state.field


def test_lost_ack_duplicate_data_and_conflicting_duplicate(tmp_path: Path):
    sa, sb, profile, vocab = _make_confirmed_pair(tmp_path)
    ctx0 = direction_message_context(sa, direction=sa.tx.direction, epoch=1, seq=0)

    prep = prepare_send(sa.tx, "red green", ctx0, profile=profile, vocab=vocab)
    sa_tx_pending = prep.pending_state

    # Receiver accepts seq=0, but ACK is lost on the wire
    res1 = validate_receive(sb.rx, prep.packet_bytes, ctx0, profile=profile, vocab=vocab)
    sb_rx_after = res1.next_state
    sb_state_snapshot = encode_direction_state(sb_rx_after)
    assert sb_rx_after.field.age == 1

    # Sender retries exact stored bytes -> receiver returns cached ACK without second learning update
    res_dup = validate_receive(sb_rx_after, prep.packet_bytes, ctx0, profile=profile, vocab=vocab)
    assert res_dup.is_duplicate is True
    assert res_dup.ack_packet_bytes == res1.ack_packet_bytes
    assert encode_direction_state(res_dup.next_state) == sb_state_snapshot
    assert res_dup.next_state.field.age == 1

    # Conflicting packet at the same seq=0 must be rejected without mutating state
    alt_prep = prepare_send(sa.tx, "blue green", ctx0, profile=profile, vocab=vocab)
    with pytest.raises(EngineError) as exc_info:
        validate_receive(sb_rx_after, alt_prep.packet_bytes, ctx0, profile=profile, vocab=vocab)
    assert exc_info.value.reason == "conflicting_duplicate_seq"
    assert encode_direction_state(sb_rx_after) == sb_state_snapshot

    # Sender resolves pending send with the retransmitted cached ACK
    sa_tx_done = validate_ack(
        sa_tx_pending, res_dup.ack_packet_bytes, profile=profile, session_id=sa.session_id
    )
    assert sa_tx_done.field == sb_rx_after.field
    assert sa_tx_done.field.age == 1  # ACK did NOT train the field a second time


def test_crossed_simultaneous_sends_and_out_of_order_gap(tmp_path: Path):
    sa, sb, profile, vocab = _make_confirmed_pair(tmp_path)

    # Both A->B (i2r) and B->A (r2i) send concurrently before either receives
    ctx_ab = direction_message_context(sa, direction=sa.tx.direction, epoch=1, seq=0)
    ctx_ba = direction_message_context(sb, direction=sb.tx.direction, epoch=1, seq=0)

    prep_ab = prepare_send(sa.tx, "red blue", ctx_ab, profile=profile, vocab=vocab)
    prep_ba = prepare_send(sb.tx, "green red", ctx_ba, profile=profile, vocab=vocab)

    sa = sa.with_tx(prep_ab.pending_state)
    sb = sb.with_tx(prep_ba.pending_state)

    # Both receive and acknowledge independently
    rx_b = validate_receive(sb.rx, prep_ab.packet_bytes, ctx_ab, profile=profile, vocab=vocab)
    rx_a = validate_receive(sa.rx, prep_ba.packet_bytes, ctx_ba, profile=profile, vocab=vocab)
    assert rx_b.plaintext == "red blue"
    assert rx_a.plaintext == "green red"

    sa = sa.with_rx(rx_a.next_state).with_tx(
        validate_ack(sa.tx, rx_b.ack_packet_bytes, profile=profile, session_id=sa.session_id)
    )
    sb = sb.with_rx(rx_b.next_state).with_tx(
        validate_ack(sb.tx, rx_a.ack_packet_bytes, profile=profile, session_id=sb.session_id)
    )

    assert sa.tx.field == sb.rx.field
    assert sb.tx.field == sa.rx.field
    assert sa.tx.field != sa.rx.field

    # Gap outside allowed sequence (sending seq=2 when receiver expects seq=1) is rejected
    ctx_gap = direction_message_context(sa, direction=sa.tx.direction, epoch=1, seq=2)
    rx_before = encode_direction_state(sb.rx)
    # Tamper seq in a fresh packet by preparing with seq=1 then testing against seq=2 context
    ctx_seq1 = direction_message_context(sa, direction=sa.tx.direction, epoch=1, seq=1)
    prep_seq1 = prepare_send(sa.tx, "blue red", ctx_seq1, profile=profile, vocab=vocab)
    with pytest.raises(EngineError) as exc_info:
        validate_receive(sb.rx, prep_seq1.packet_bytes, ctx_gap, profile=profile, vocab=vocab)
    assert exc_info.value.reason == "seq_mismatch"
    assert encode_direction_state(sb.rx) == rx_before
