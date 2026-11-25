"""Regression tests for the 4 delivery and storage findings on commit 0de79fb.

1. Lost ACK followed by receiver epoch transition must NOT strand the sender.
2. Sender must reject expanded text > MAX_TEXT_BYTES before committing pending_send.
3. Backup-restored closed directions cannot be reopened by save_session(old_session)
   and cannot return pending bytes from get_pending_packet_bytes.
4. Authenticated-store consistency: apply_ack verifies the pending outbox row+MAC,
   and duplicate commit_received verifies the inbox row MAC (catching altered plaintext).
"""

from __future__ import annotations

import json
import sqlite3
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
from core.vocab_codec import MAX_TEXT_BYTES, load_vocab
from hive.engine_v3 import (
    EngineError,
    direction_message_context,
    prepare_send,
    validate_ack,
    validate_receive,
)
from hive.epochs_v3 import apply_epoch_event_v3, create_epoch_event_v3
from hive.key_schedule_v3 import (
    compute_handshake_confirm,
    establish_confirmed_session,
    initialize_session,
)
from hive.state_store_v3 import (
    StateStoreError,
    StateStoreV3,
    apply_ack,
    commit_prepared_send,
    commit_received,
)
from tests.v3.test_transactions import _make_confirmed_pair


def test_lost_ack_followed_by_receiver_epoch_transition_recovers_cleanly(tmp_path: Path):
    sa, sb, profile, vocab = _make_confirmed_pair(tmp_path)
    auth_key = b"\xee" * 32
    ev2 = create_epoch_event_v3(auth_key, bundle_id=profile.bundle_id, target_epoch=2, block_hash=b"\x02" * 32)

    # 1. Sender prepares (epoch=1, seq=0); receiver accepts it, but ACK is lost on the wire
    ctx_e1 = direction_message_context(sa, direction=sa.tx.direction, epoch=1, seq=0)
    prep0 = prepare_send(sa.tx, "red blue", ctx_e1, profile=profile, vocab=vocab)
    res0 = validate_receive(sb.rx, prep0.packet_bytes, ctx_e1, profile=profile, vocab=vocab)
    assert res0.plaintext == "red blue"
    sb_rx_after_e1 = res0.next_state

    # 2. Receiver rotates to epoch=2 before sender receives the epoch=1 ACK
    sb_rx_e2, applied_b = apply_epoch_event_v3(sb_rx_after_e1, ev2, authority_key=auth_key, profile=profile)
    assert applied_b is True
    assert sb_rx_e2.epoch == 2 and sb_rx_e2.next_seq == 0
    rx_e2_snap = encode_direction_state(sb_rx_e2)

    # 3. Sender retransmits exact old (epoch=1, seq=0) packet -> receiver returns cached ACK!
    res_dup = validate_receive(sb_rx_e2, prep0.packet_bytes, ctx_e1, profile=profile, vocab=vocab)
    assert res_dup.is_duplicate is True
    assert res_dup.ack_packet_bytes == res0.ack_packet_bytes
    assert encode_direction_state(res_dup.next_state) == rx_e2_snap

    # 4. Sender applies cached epoch=1 ACK, drains pending_send, rotates to epoch=2, and continues!
    sa_tx_drained = validate_ack(
        prep0.pending_state, res_dup.ack_packet_bytes, profile=profile, session_id=sa.session_id
    )
    sa_tx_e2, applied_a = apply_epoch_event_v3(sa_tx_drained, ev2, authority_key=auth_key, profile=profile)
    assert applied_a is True

    ctx_e2 = direction_message_context(sa, direction=sa_tx_e2.direction, epoch=2, seq=0)
    prep_e2 = prepare_send(sa_tx_e2, "green red", ctx_e2, profile=profile, vocab=vocab)
    res_e2 = validate_receive(sb_rx_e2, prep_e2.packet_bytes, ctx_e2, profile=profile, vocab=vocab)
    assert res_e2.plaintext == "green red"


def test_sender_rejects_expanded_text_exceeding_max_text_bytes_before_mutation(tmp_path: Path):
    big_tok = "A" * 1024
    vp = tmp_path / "big_vocab.json"
    vp.write_text(json.dumps([big_tok, " "]), encoding="utf-8")
    vocab = load_vocab(str(vp))
    profile = ProfileV3(
        bundle_id=b"\xcd" * 16,
        expected_vocab_digest=compute_vocab_digest_v3(vocab),
    )
    net_sec, fld_sec = b"\x11" * 32, b"\x22" * 32
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

    # 1025 * 1024 = 1,049,600 bytes > MAX_TEXT_BYTES (1,048,576), even though wire blob is ~3,100 bytes
    oversize_expanded = big_tok * ((MAX_TEXT_BYTES // 1024) + 1)
    assert len(oversize_expanded.encode("utf-8")) > MAX_TEXT_BYTES

    tx_before = encode_direction_state(sa.tx)
    ctx0 = direction_message_context(sa, direction=sa.tx.direction, epoch=1, seq=0)
    with pytest.raises(EngineError) as exc_info:
        prepare_send(sa.tx, oversize_expanded, ctx0, profile=profile, vocab=vocab)
    assert "text_too_large" in str(exc_info.value)
    assert encode_direction_state(sa.tx) == tx_before


def test_closed_direction_cannot_reopen_or_retransmit_after_backup_restore(tmp_path: Path):
    sa, _sb, profile, vocab = _make_confirmed_pair(tmp_path)
    db = tmp_path / "closed.sqlite"
    store = StateStoreV3(db, storage_key=b"\xaa" * 32)
    store.save_session(sa)

    # Commit a pending send, then simulate administrative backup restore
    ctx0 = direction_message_context(sa, direction=sa.tx.direction, epoch=1, seq=0)
    prep0 = prepare_send(sa.tx, "red blue", ctx0, profile=profile, vocab=vocab)
    commit_prepared_send(store, prep0, session_id=sa.session_id)

    closed_n = store.invalidate_all_sessions_after_backup_restore()
    assert closed_n == 2

    # 1. Retry accessor MUST refuse closed direction
    with pytest.raises(StateStoreError) as exc_retry:
        store.get_pending_packet_bytes(sa.session_id, sa.tx.direction)
    assert exc_retry.value.reason == "closed_direction"

    # 2. Calling save_session(old_open_session) MUST NOT reopen closed directions
    with pytest.raises(StateStoreError) as exc_reopen:
        store.save_session(sa)
    assert exc_reopen.value.reason == "cannot_reopen_closed_direction"
    assert store.load_direction(sa.session_id, sa.tx.direction).closed is True
    store.close()


def test_authenticated_store_consistency_on_deleted_outbox_and_tampered_duplicate_inbox(tmp_path: Path):
    sa, sb, profile, vocab = _make_confirmed_pair(tmp_path)
    db_a = tmp_path / "a.sqlite"
    db_b = tmp_path / "b.sqlite"
    store_a = StateStoreV3(db_a, storage_key=b"\xaa" * 32)
    store_b = StateStoreV3(db_b, storage_key=b"\xbb" * 32)
    store_a.save_session(sa)
    store_b.save_session(sb)

    ctx0 = direction_message_context(sa, direction=sa.tx.direction, epoch=1, seq=0)
    prep0 = prepare_send(sa.tx, "red blue", ctx0, profile=profile, vocab=vocab)
    commit_prepared_send(store_a, prep0, session_id=sa.session_id)

    val0 = validate_receive(sb.rx, prep0.packet_bytes, ctx0, profile=profile, vocab=vocab)
    commit_received(store_b, val0, session_id=sb.session_id)

    # Case A0: Non-ASCII corrupted outbox status raises structured StateStoreError (not UnicodeEncodeError)
    raw_a = sqlite3.connect(str(db_a))
    raw_a.execute("UPDATE outbox SET status = 'pénding-💥';")
    raw_a.commit()
    raw_a.close()

    with pytest.raises(StateStoreError) as exc_non_ascii:
        store_a.get_pending_packet_bytes(sa.session_id, sa.tx.direction)
    assert exc_non_ascii.value.reason == "corrupt_or_tampered_outbox"

    with pytest.raises(StateStoreError) as exc_non_ascii_ack:
        apply_ack(
            store_a,
            val0.ack_packet_bytes,
            session_id=sa.session_id,
            direction=sa.tx.direction,
            profile=profile,
        )
    assert exc_non_ascii_ack.value.reason == "corrupt_or_tampered_outbox"

    # Case A: Delete pending outbox row in SQLite -> apply_ack MUST fail closed
    raw_a = sqlite3.connect(str(db_a))
    raw_a.execute("DELETE FROM outbox;")
    raw_a.commit()
    raw_a.close()

    with pytest.raises(StateStoreError) as exc_ob:
        apply_ack(
            store_a,
            val0.ack_packet_bytes,
            session_id=sa.session_id,
            direction=sa.tx.direction,
            profile=profile,
        )
    assert exc_ob.value.reason == "inconsistent_outbox"
    assert store_a.load_direction(sa.session_id, sa.tx.direction).pending_send is not None

    # Case B: Alter inbox plaintext in SQLite -> duplicate commit_received MUST fail MAC check
    raw_b = sqlite3.connect(str(db_b))
    raw_b.execute("UPDATE inbox SET plaintext = 'tampered text';")
    raw_b.commit()
    raw_b.close()

    rx_b = store_b.load_direction(sb.session_id, sb.rx.direction)
    val0_dup = validate_receive(rx_b, prep0.packet_bytes, ctx0, profile=profile, vocab=vocab)
    assert val0_dup.is_duplicate is True
    with pytest.raises(StateStoreError) as exc_inb:
        commit_received(store_b, val0_dup, session_id=sb.session_id)
    assert exc_inb.value.reason == "corrupt_or_tampered_inbox"

    store_a.close()
    store_b.close()
