"""IDRE v3 Stateful Runtime Node (wrapping engine_v3, key_schedule_v3, state_store_v3, epochs_v3).

Bridges pure functional protocol operations with durable SQLite persistence
and thread-safe session management. Never falls back to v2 or legacy bypasses.
"""

from __future__ import annotations

import secrets
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.profile_v3 import (
    BUNDLE_ID_BYTES,
    HANDSHAKE_NONCE_BYTES,
    SESSION_ID_BYTES,
    ProfileV3,
    ProvisioningBundleV3,
    TranscriptV3,
    canonical_profile,
    public_profile_metadata,
)
from core.session_v3 import DirectionStateV3, SessionV3
from core.vocab_codec import Vocab
from hive.engine_v3 import (
    EngineError,
    direction_message_context,
    prepare_send,
    validate_receive,
)
from hive.epochs_v3 import (
    EpochControlError,
    EpochEventV3,
    apply_epoch_event_v3,
    force_session_v3,
    fork_multiverse_timeline_v3,
    open_offline_envelope_v3,
)
from hive.key_schedule_v3 import (
    KeyScheduleError,
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


class FieldBoundNodeV3:
    """Thread-safe IDRE v3 runtime node backed by an authenticated SQLite StateStoreV3."""

    def __init__(
        self,
        *,
        bundle: ProvisioningBundleV3,
        vocab: Vocab,
        db_path: str | Path,
        storage_key: bytes,
    ) -> None:
        bundle.validate(vocab)
        self.bundle = bundle
        self.profile: ProfileV3 = bundle.profile
        self.vocab = vocab
        self.node_id = bundle.local_node_id
        self.store = StateStoreV3(db_path, storage_key=storage_key)
        self._lock = threading.RLock()
        self._sessions: Dict[str, SessionV3] = self.store.load_sessions(
            profile=self.profile,
            local_node_id=self.node_id,
        )
        self._pending_init: Dict[str, Tuple[bytes, bytes]] = {}  # peer_id -> (session_id, init_nonce)
        self._pending_resp: Dict[str, Tuple[TranscriptV3, SessionV3]] = {}  # peer_id -> (transcript, candidate)

    def close(self) -> None:
        with self._lock:
            self.store.close()

    def hello(self) -> Dict[str, Any]:
        """Return non-secret public metadata (never exposes private digests or secrets)."""
        meta = public_profile_metadata(self.profile)
        meta["node_id"] = self.node_id
        return meta

    def handshake_init(self, peer_id: str) -> Dict[str, str]:
        """Initiator step 1: generate fresh session_id and 32-byte initiator nonce."""
        with self._lock:
            sid = secrets.token_bytes(SESSION_ID_BYTES)
            nonce = secrets.token_bytes(HANDSHAKE_NONCE_BYTES)
            self._pending_init[str(peer_id)] = (sid, nonce)
            return {
                "bundle_id_hex": self.profile.bundle_id.hex(),
                "session_id_hex": sid.hex(),
                "initiator_id": self.node_id,
                "initiator_nonce_hex": nonce.hex(),
            }

    def handshake_respond(self, init_msg: Dict[str, str]) -> Dict[str, str]:
        """Responder step 2: generate responder nonce, stage candidate session, return confirm tag."""
        with self._lock:
            bundle_id = bytes.fromhex(str(init_msg["bundle_id_hex"]))
            if bundle_id != self.profile.bundle_id:
                raise KeyScheduleError("bundle_id_mismatch")
            sid = bytes.fromhex(str(init_msg["session_id_hex"]))
            initiator_id = str(init_msg["initiator_id"])
            init_nonce = bytes.fromhex(str(init_msg["initiator_nonce_hex"]))
            resp_nonce = secrets.token_bytes(HANDSHAKE_NONCE_BYTES)

            tr = TranscriptV3(
                profile_bytes=canonical_profile(self.profile),
                session_id=sid,
                initiator_id=initiator_id,
                responder_id=self.node_id,
                initiator_nonce=init_nonce,
                responder_nonce=resp_nonce,
            )
            cand = initialize_session(self.bundle, tr)
            resp_confirm = compute_handshake_confirm(self.bundle, cand)
            self._pending_resp[initiator_id] = (tr, cand)
            return {
                "session_id_hex": sid.hex(),
                "responder_id": self.node_id,
                "responder_nonce_hex": resp_nonce.hex(),
                "responder_confirm_hex": resp_confirm.hex(),
            }

    def handshake_finish_initiator(self, peer_id: str, resp_msg: Dict[str, str]) -> Dict[str, str]:
        """Initiator step 3: verify responder confirm, commit durable session, return initiator confirm."""
        with self._lock:
            pid = str(peer_id)
            if pid not in self._pending_init:
                raise KeyScheduleError("no_pending_handshake_init")
            sid, init_nonce = self._pending_init[pid]
            if bytes.fromhex(str(resp_msg["session_id_hex"])) != sid:
                raise KeyScheduleError("session_id_mismatch")
            resp_id = str(resp_msg["responder_id"])
            if resp_id != pid:
                raise KeyScheduleError("responder_id_mismatch")
            resp_nonce = bytes.fromhex(str(resp_msg["responder_nonce_hex"]))
            resp_confirm = bytes.fromhex(str(resp_msg["responder_confirm_hex"]))

            tr = TranscriptV3(
                profile_bytes=canonical_profile(self.profile),
                session_id=sid,
                initiator_id=self.node_id,
                responder_id=resp_id,
                initiator_nonce=init_nonce,
                responder_nonce=resp_nonce,
            )
            sess = establish_confirmed_session(self.bundle, tr, peer_confirm_tag=resp_confirm)
            init_confirm = compute_handshake_confirm(self.bundle, sess)
            self.store.save_session(sess)
            self._sessions[pid] = sess
            self._pending_init.pop(pid, None)
            return {
                "session_id_hex": sid.hex(),
                "initiator_id": self.node_id,
                "initiator_confirm_hex": init_confirm.hex(),
            }

    def handshake_finish_responder(self, peer_id: str, finish_msg: Dict[str, str]) -> bool:
        """Responder step 4: verify initiator confirm and commit durable session."""
        with self._lock:
            pid = str(peer_id)
            if pid not in self._pending_resp:
                raise KeyScheduleError("no_pending_handshake_resp")
            tr, _cand = self._pending_resp[pid]
            if bytes.fromhex(str(finish_msg["session_id_hex"])) != tr.session_id:
                raise KeyScheduleError("session_id_mismatch")
            init_confirm = bytes.fromhex(str(finish_msg["initiator_confirm_hex"]))
            sess = establish_confirmed_session(self.bundle, tr, peer_confirm_tag=init_confirm)
            self.store.save_session(sess)
            self._sessions[pid] = sess
            self._pending_resp.pop(pid, None)
            return True

    def _require_session(self, peer_id: str) -> SessionV3:
        pid = str(peer_id)
        if pid not in self._sessions:
            raise EngineError("unknown_session", f"no confirmed v3 session with {pid}")
        return self._sessions[pid]

    def send(self, peer_id: str, content: str) -> bytes:
        """Prepare and durably commit a strict v3 DATA packet; return exact wire bytes."""
        with self._lock:
            sess = self._require_session(peer_id)
            tx = self.store.load_direction(sess.session_id, sess.tx.direction)
            ctx = direction_message_context(
                sess, direction=tx.direction, epoch=tx.epoch, seq=tx.next_seq
            )
            prep = prepare_send(tx, content, ctx, profile=self.profile, vocab=self.vocab)
            commit_prepared_send(self.store, prep, session_id=sess.session_id)
            return prep.packet_bytes

    def retransmit(self, peer_id: str) -> Optional[bytes]:
        """Return exact stored pending packet bytes for stop-and-wait retry, or None if idle."""
        with self._lock:
            sess = self._require_session(peer_id)
            return self.store.get_pending_packet_bytes(sess.session_id, sess.tx.direction)

    def receive(self, peer_id: str, packet_bytes: bytes) -> Dict[str, Any]:
        """Atomically validate and durably commit an incoming v3 DATA packet."""
        with self._lock:
            try:
                sess = self._require_session(peer_id)
                rx = self.store.load_direction(sess.session_id, sess.rx.direction)
                ctx = direction_message_context(
                    sess, direction=rx.direction, epoch=rx.epoch, seq=rx.next_seq
                )
                val = validate_receive(rx, packet_bytes, ctx, profile=self.profile, vocab=self.vocab)
                commit_received(self.store, val, session_id=sess.session_id)
                return {
                    "status": "duplicate" if val.is_duplicate else "delivered",
                    "epoch": val.epoch,
                    "seq": val.seq,
                    "ack_hex": val.ack_packet_bytes.hex(),
                }
            except (EngineError, StateStoreError) as exc:
                return {"status": "reject", "reason": exc.reason}

    def process_ack(self, peer_id: str, ack_bytes: bytes) -> Dict[str, Any]:
        """Validate an authenticated control ACK and resolve pending send atomically."""
        with self._lock:
            try:
                sess = self._require_session(peer_id)
                res = apply_ack(
                    self.store,
                    ack_bytes,
                    session_id=sess.session_id,
                    direction=sess.tx.direction,
                    profile=self.profile,
                )
                return {
                    "status": "acked",
                    "resolved": res.resolved,
                    "new_next_seq": res.new_next_seq,
                    "new_field_age": res.new_field_age,
                }
            except (EngineError, StateStoreError) as exc:
                return {"status": "reject", "reason": exc.reason}

    def inbox(self, peer_id: str) -> List[Dict[str, Any]]:
        """Return all verified durable inbox records from `peer_id`."""
        with self._lock:
            sess = self._require_session(peer_id)
            recs = self.store.list_inbox(sess.session_id, sess.rx.direction)
            return [
                {
                    "epoch": r.delivery_id.epoch,
                    "seq": r.delivery_id.seq,
                    "packet_digest_hex": r.packet_digest.hex(),
                    "plaintext": r.plaintext,
                }
                for r in recs
            ]

    def apply_epoch(self, peer_id: str, event: EpochEventV3, *, authority_key: bytes) -> Dict[str, Any]:
        """Apply a coordinated epoch event to both tx and rx directions atomically."""
        with self._lock:
            sess = self._require_session(peer_id)
            tx = self.store.load_direction(sess.session_id, sess.tx.direction)
            rx = self.store.load_direction(sess.session_id, sess.rx.direction)
            next_tx, app_tx = apply_epoch_event_v3(tx, event, authority_key=authority_key, profile=self.profile)
            next_rx, app_rx = apply_epoch_event_v3(rx, event, authority_key=authority_key, profile=self.profile)
            if app_tx or app_rx:
                self.store.save_session(sess.with_tx(next_tx).with_rx(next_rx))
            return {"applied_tx": app_tx, "applied_rx": app_rx, "epoch": next_tx.epoch}

    # Explicitly disabled legacy v2 bypass routes
    def force_session(self, *args, **kwargs) -> None:
        force_session_v3(*args, **kwargs)

    def ingest_offline_envelope(self, *args, **kwargs) -> None:
        open_offline_envelope_v3(*args, **kwargs)

    def fork_multiverse(self, *args, **kwargs) -> None:
        fork_multiverse_timeline_v3(*args, **kwargs)
