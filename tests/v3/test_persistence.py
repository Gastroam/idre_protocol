"""Tests for Task 8: Authenticated SQLite durable state store, crash injection, and fail-closed recovery."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from hive.engine_v3 import direction_message_context, prepare_send, validate_receive
from hive.state_store_v3 import (
    StateStoreError,
    StateStoreV3,
    apply_ack,
    commit_prepared_send,
    commit_received,
)
from tests.v3.test_transactions import _make_confirmed_pair


class SimulatedCrash(RuntimeError):
    """Deterministic crash injected at a durable transaction boundary."""


def _make_crash_hook(target_point: str):
    def _hook(point: str) -> None:
        if point == target_point:
            raise SimulatedCrash(f"crashed at {point}")

    return _hook


def test_crash_before_and_after_send_receive_and_ack_boundaries(tmp_path: Path):
    sa, sb, profile, vocab = _make_confirmed_pair(tmp_path)
    key_a = b"\xaa" * 32
    key_b = b"\xbb" * 32
    db_a = tmp_path / "node_a.sqlite"
    db_b = tmp_path / "node_b.sqlite"

    # Initial durable session commit on both peers
    store_a = StateStoreV3(db_a, storage_key=key_a)
    store_b = StateStoreV3(db_b, storage_key=key_b)
    store_a.save_session(sa)
    store_b.save_session(sb)
    store_a.close()
    store_b.close()

    # 1. Crash BEFORE send commit -> rollback, no pending outbox
    store_a = StateStoreV3(db_a, storage_key=key_a, crash_hook=_make_crash_hook("before_send_commit"))
    tx_state = store_a.load_direction(sa.session_id, sa.tx.direction)
    ctx0 = direction_message_context(sa, direction=sa.tx.direction, epoch=1, seq=0)
    prep0 = prepare_send(tx_state, "red blue", ctx0, profile=profile, vocab=vocab)
    with pytest.raises(SimulatedCrash):
        commit_prepared_send(store_a, prep0, session_id=sa.session_id)
    store_a.close()

    store_a = StateStoreV3(db_a, storage_key=key_a)
    assert store_a.get_pending_packet_bytes(sa.session_id, sa.tx.direction) is None
    store_a.close()

    # 2. Crash AFTER send commit (before wire transmission) -> restart retries exact stored bytes
    store_a = StateStoreV3(db_a, storage_key=key_a, crash_hook=_make_crash_hook("after_send_commit"))
    with pytest.raises(SimulatedCrash):
        commit_prepared_send(store_a, prep0, session_id=sa.session_id)
    store_a.close()

    store_a = StateStoreV3(db_a, storage_key=key_a)
    pending_wire_bytes = store_a.get_pending_packet_bytes(sa.session_id, sa.tx.direction)
    assert pending_wire_bytes == prep0.packet_bytes
    store_a.close()

    # 3. Crash AFTER receiver commit (before ACK delivered) -> sender retry gets cached ACK, 1 inbox row
    store_b = StateStoreV3(db_b, storage_key=key_b, crash_hook=_make_crash_hook("after_receive_commit"))
    rx_state = store_b.load_direction(sb.session_id, sb.rx.direction)
    val0 = validate_receive(rx_state, pending_wire_bytes, ctx0, profile=profile, vocab=vocab)
    with pytest.raises(SimulatedCrash):
        commit_received(store_b, val0, session_id=sb.session_id)
    store_b.close()

    # Restart B and process exact retry from A
    store_b = StateStoreV3(db_b, storage_key=key_b)
    rx_restarted = store_b.load_direction(sb.session_id, sb.rx.direction)
    val0_dup = validate_receive(rx_restarted, pending_wire_bytes, ctx0, profile=profile, vocab=vocab)
    assert val0_dup.is_duplicate is True
    commit_received(store_b, val0_dup, session_id=sb.session_id)
    inbox_b = store_b.list_inbox(sb.session_id, sb.rx.direction)
    assert len(inbox_b) == 1
    assert inbox_b[0].plaintext == "red blue"
    assert store_b.load_direction(sb.session_id, sb.rx.direction).field.age == 1
    store_b.close()

    # 4. Crash BEFORE ACK commit on A -> restart still has pending send; re-applying ACK resolves cleanly
    store_a = StateStoreV3(db_a, storage_key=key_a, crash_hook=_make_crash_hook("before_ack_commit"))
    with pytest.raises(SimulatedCrash):
        apply_ack(
            store_a,
            val0_dup.ack_packet_bytes,
            session_id=sa.session_id,
            direction=sa.tx.direction,
            profile=profile,
        )
    store_a.close()

    store_a = StateStoreV3(db_a, storage_key=key_a)
    assert store_a.get_pending_packet_bytes(sa.session_id, sa.tx.direction) == prep0.packet_bytes
    ack_res = apply_ack(
        store_a,
        val0_dup.ack_packet_bytes,
        session_id=sa.session_id,
        direction=sa.tx.direction,
        profile=profile,
    )
    assert ack_res.resolved is True
    assert ack_res.new_next_seq == 1
    assert ack_res.new_field_age == 1
    assert store_a.get_pending_packet_bytes(sa.session_id, sa.tx.direction) is None
    store_a.close()


def test_missing_tampered_and_backup_restored_store_fail_closed(tmp_path: Path):
    sa, sb, profile, vocab = _make_confirmed_pair(tmp_path)
    key_a = b"\xaa" * 32
    db_a = tmp_path / "fail_closed.sqlite"

    # Missing session state fails closed (never silently recreates from provisioning)
    store = StateStoreV3(db_a, storage_key=key_a)
    with pytest.raises(StateStoreError) as exc_missing:
        store.load_direction(sa.session_id, sa.tx.direction)
    assert exc_missing.value.reason == "missing_session_state"

    store.save_session(sa)
    store.close()

    # Administrative backup restore closes all persisted directions -> must rekey
    store = StateStoreV3(db_a, storage_key=key_a)
    closed_n = store.invalidate_all_sessions_after_backup_restore()
    assert closed_n == 2
    assert store.load_direction(sa.session_id, sa.tx.direction).closed is True
    store.close()

    # Tampering with persisted state_blob fails MAC verification on load
    raw_conn = sqlite3.connect(str(db_a))
    raw_conn.execute(
        "UPDATE direction_states SET state_blob = X'deadbeef' WHERE direction = ?;",
        (sa.tx.direction,),
    )
    raw_conn.commit()
    raw_conn.close()

    store = StateStoreV3(db_a, storage_key=key_a)
    with pytest.raises(StateStoreError) as exc_tamper:
        store.load_direction(sa.session_id, sa.tx.direction)
    assert exc_tamper.value.reason == "corrupt_or_tampered_state"
    store.close()
