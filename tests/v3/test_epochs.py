"""Tests for Task 10: Coordinated, authenticated, idempotent epoch control and post-epoch field binding."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from core.field_state_v3 import AcceptedEventV3, advance_field
from core.session_v3 import encode_direction_state
from hive.engine_v3 import EngineError, direction_message_context, prepare_send, validate_ack, validate_receive
from hive.epochs_v3 import EpochControlError, apply_epoch_event_v3, create_epoch_event_v3
from tests.v3.test_transactions import _make_confirmed_pair


def test_epoch_control_ordering_idempotency_auth_and_post_epoch_field_binding(tmp_path: Path):
    sa, sb, profile, vocab = _make_confirmed_pair(tmp_path)
    auth_key = b"\xee" * 32
    block2 = b"\x02" * 32
    ev2 = create_epoch_event_v3(auth_key, bundle_id=profile.bundle_id, target_epoch=2, block_hash=block2)

    # Unauthorized / forged MAC rejected
    forged = replace(ev2, authority_mac=b"\x00" * 32)
    with pytest.raises(EpochControlError) as exc_auth:
        apply_epoch_event_v3(sa.tx, forged, authority_key=auth_key, profile=profile)
    assert exc_auth.value.reason == "invalid_epoch_authority_mac"

    # Out-of-order epoch (jumping 1 -> 3) rejected
    ev3 = create_epoch_event_v3(auth_key, bundle_id=profile.bundle_id, target_epoch=3, block_hash=b"\x03" * 32)
    with pytest.raises(EpochControlError) as exc_ooo:
        apply_epoch_event_v3(sa.tx, ev3, authority_key=auth_key, profile=profile)
    assert exc_ooo.value.reason == "out_of_order_epoch"

    # Pending old-epoch packet must drain before rotating
    ctx0 = direction_message_context(sa, direction=sa.tx.direction, epoch=1, seq=0)
    prep0 = prepare_send(sa.tx, "red blue", ctx0, profile=profile, vocab=vocab)
    with pytest.raises(EpochControlError) as exc_pend:
        apply_epoch_event_v3(prep0.pending_state, ev2, authority_key=auth_key, profile=profile)
    assert exc_pend.value.reason == "pending_send_must_drain_before_epoch"

    # Drain seq=0 cleanly, then apply epoch=2 on both peers
    res0 = validate_receive(sb.rx, prep0.packet_bytes, ctx0, profile=profile, vocab=vocab)
    sb = sb.with_rx(res0.next_state)
    sa = sa.with_tx(validate_ack(prep0.pending_state, res0.ack_packet_bytes, profile=profile, session_id=sa.session_id))

    tx_e2, applied_a = apply_epoch_event_v3(sa.tx, ev2, authority_key=auth_key, profile=profile)
    rx_e2, applied_b = apply_epoch_event_v3(sb.rx, ev2, authority_key=auth_key, profile=profile)
    assert applied_a is True and applied_b is True
    assert tx_e2.epoch == 2 and tx_e2.next_seq == 0
    assert rx_e2.epoch == 2 and rx_e2.next_seq == 0

    # Idempotent duplicate notification does NOT advance twice
    tx_dup, applied_dup = apply_epoch_event_v3(tx_e2, ev2, authority_key=auth_key, profile=profile)
    assert applied_dup is False
    assert encode_direction_state(tx_dup) == encode_direction_state(tx_e2)

    # Conflicting block hash at same epoch=2 is rejected
    ev2_conflict = create_epoch_event_v3(auth_key, bundle_id=profile.bundle_id, target_epoch=2, block_hash=b"\xff" * 32)
    with pytest.raises(EpochControlError) as exc_conf:
        apply_epoch_event_v3(tx_e2, ev2_conflict, authority_key=auth_key, profile=profile)
    assert exc_conf.value.reason == "conflicting_epoch_event"

    # Post-epoch DATA still requires matching FieldStateV3 (closing v2 Ouroboros bypass!)
    ctx_e2 = direction_message_context(sa, direction=tx_e2.direction, epoch=2, seq=0)
    prep_e2 = prepare_send(tx_e2, "blue green", ctx_e2, profile=profile, vocab=vocab)

    drifted_rx_e2 = replace(
        rx_e2, field=advance_field(rx_e2.field, AcceptedEventV3("data_accepted", seq=77, epoch=2))
    )
    with pytest.raises(EngineError) as exc_drift:
        validate_receive(drifted_rx_e2, prep_e2.packet_bytes, ctx_e2, profile=profile, vocab=vocab)
    assert exc_drift.value.reason == "field_or_mac_mismatch"

    # Matching field in epoch=2 succeeds
    res_e2 = validate_receive(rx_e2, prep_e2.packet_bytes, ctx_e2, profile=profile, vocab=vocab)
    assert res_e2.plaintext == "blue green"
