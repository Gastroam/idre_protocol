"""IDRE v3 Durable Atomic State Store (Task 8).

SQLite-backed transactional persistence for directional state, outbox, inbox,
and idempotent duplicate/ACK records.

Storage Security & Rollback Boundary:
- Each persisted direction state, outbox row, and inbox row is authenticated
  with HMAC-SHA-256 under a caller-supplied 32-byte `storage_key`.
- This detects local tampering and partial/corrupt writes (fail-closed).
- It does NOT by itself detect whole-database rollback to an older valid
  checkpoint without an independently protected external monotonic reference.
- Administrative backup restoration MUST close old sessions and establish a
  fresh authenticated session rather than resuming old key/counter contexts.
- Exactly-once durable inbox insertion is guaranteed by the store; callers
  requiring exactly-once external application effects must use `DeliveryIdV3`
  transactionally or idempotently.
"""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
import struct
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, List, Optional

from core.profile_v3 import MAX_UINT64, ProfileV3
from core.session_v3 import (
    DirectionStateV3,
    PreparedSendV3,
    SessionV3,
    ValidatedReceiveV3,
    decode_direction_state,
    encode_direction_state,
)
from hive.engine_v3 import EngineError, validate_ack


class StateStoreError(ValueError):
    """Raised when durable state is missing, tampered, corrupt, or closed."""

    def __init__(self, reason: str, message: str = "") -> None:
        self.reason = reason
        super().__init__(message or reason)


@dataclass(frozen=True)
class OutboxIdV3:
    session_id: bytes
    direction: str
    epoch: int
    seq: int


@dataclass(frozen=True)
class DeliveryIdV3:
    session_id: bytes
    direction: str
    epoch: int
    seq: int


@dataclass(frozen=True)
class AckResultV3:
    resolved: bool
    outbox_id: OutboxIdV3
    new_next_seq: int
    new_field_age: int


@dataclass(frozen=True)
class InboxRecordV3:
    delivery_id: DeliveryIdV3
    packet_digest: bytes
    plaintext: str


class StateStoreV3:
    """Atomic SQLite state store for IDRE v3 directional sessions."""

    SCHEMA_VERSION = 1

    def __init__(
        self,
        db_path: str | Path,
        *,
        storage_key: bytes,
        crash_hook: Optional[Callable[[str], None]] = None,
    ) -> None:
        if not isinstance(storage_key, (bytes, bytearray)) or len(storage_key) < 32:
            raise StateStoreError("bad_storage_key", "storage_key must be at least 32 bytes")
        self._db_path = str(db_path)
        self._storage_key = bytes(storage_key)
        self._crash_hook = crash_hook
        self._conn = sqlite3.connect(self._db_path, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=FULL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._init_schema()

    def _fire_hook(self, point: str) -> None:
        if self._crash_hook is not None:
            self._crash_hook(point)

    def _mac(self, domain: bytes, *parts: bytes) -> bytes:
        h = hmac.new(self._storage_key, domain, hashlib.sha256)
        for p in parts:
            h.update(struct.pack(">I", len(p)))
            h.update(p)
        return h.digest()

    def _init_schema(self) -> None:
        self._conn.execute("BEGIN IMMEDIATE;")
        try:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS store_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS direction_states (
                    session_id BLOB NOT NULL,
                    direction TEXT NOT NULL,
                    state_blob BLOB NOT NULL,
                    state_mac BLOB NOT NULL,
                    PRIMARY KEY (session_id, direction)
                );
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS outbox (
                    session_id BLOB NOT NULL,
                    direction TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    seq INTEGER NOT NULL,
                    packet_bytes BLOB NOT NULL,
                    packet_digest BLOB NOT NULL,
                    status TEXT NOT NULL,
                    row_mac BLOB NOT NULL,
                    PRIMARY KEY (session_id, direction, epoch, seq)
                );
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS inbox (
                    session_id BLOB NOT NULL,
                    direction TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    seq INTEGER NOT NULL,
                    packet_digest BLOB NOT NULL,
                    plaintext TEXT NOT NULL,
                    row_mac BLOB NOT NULL,
                    PRIMARY KEY (session_id, direction, epoch, seq)
                );
                """
            )
            row = self._conn.execute(
                "SELECT value FROM store_meta WHERE key = 'schema_version';"
            ).fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO store_meta(key, value) VALUES ('schema_version', ?);",
                    (str(self.SCHEMA_VERSION),),
                )
            elif int(row[0]) != self.SCHEMA_VERSION:
                raise StateStoreError("unsupported_schema_version", f"got {row[0]}")
            self._conn.execute("COMMIT;")
        except Exception:
            self._conn.execute("ROLLBACK;")
            raise

    def close(self) -> None:
        self._conn.close()

    def _put_direction_in_tx(self, session_id: bytes, state: DirectionStateV3) -> None:
        blob = encode_direction_state(state)
        mac = self._mac(b"IDRE-V3-STORE-DIR", session_id, state.direction.encode("ascii"), blob)
        self._conn.execute(
            """
            INSERT INTO direction_states(session_id, direction, state_blob, state_mac)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(session_id, direction) DO UPDATE SET
                state_blob = excluded.state_blob,
                state_mac = excluded.state_mac;
            """,
            (session_id, state.direction, blob, mac),
        )

    def _get_direction_in_tx(self, session_id: bytes, direction: str) -> DirectionStateV3:
        row = self._conn.execute(
            "SELECT state_blob, state_mac FROM direction_states WHERE session_id = ? AND direction = ?;",
            (session_id, direction),
        ).fetchone()
        if row is None:
            raise StateStoreError("missing_session_state", f"no state for direction={direction}")
        blob, mac = bytes(row[0]), bytes(row[1])
        expected = self._mac(b"IDRE-V3-STORE-DIR", session_id, direction.encode("ascii"), blob)
        if not hmac.compare_digest(mac, expected):
            raise StateStoreError("corrupt_or_tampered_state", "direction state MAC verification failed")
        try:
            return decode_direction_state(blob)
        except Exception as exc:
            raise StateStoreError("corrupt_or_tampered_state", str(exc)) from exc

    def save_session(self, session: SessionV3) -> None:
        """Persist both directional states of a newly confirmed SessionV3 atomically."""
        self._conn.execute("BEGIN IMMEDIATE;")
        try:
            self._put_direction_in_tx(session.session_id, session.tx)
            self._put_direction_in_tx(session.session_id, session.rx)
            self._conn.execute("COMMIT;")
        except Exception:
            self._conn.execute("ROLLBACK;")
            raise

    def load_direction(self, session_id: bytes, direction: str) -> DirectionStateV3:
        """Load and verify a persisted directional state; fails closed if missing or tampered."""
        return self._get_direction_in_tx(session_id, direction)

    def get_pending_packet_bytes(self, session_id: bytes, direction: str) -> Optional[bytes]:
        """Return exact stored pending packet bytes for retransmission, or None if idle."""
        state = self.load_direction(session_id, direction)
        if state.pending_send is None:
            return None
        ps = state.pending_send
        row = self._conn.execute(
            """
            SELECT packet_bytes, packet_digest, status, row_mac
            FROM outbox
            WHERE session_id = ? AND direction = ? AND epoch = ? AND seq = ?;
            """,
            (session_id, direction, ps.epoch, ps.seq),
        ).fetchone()
        if row is None:
            raise StateStoreError("inconsistent_outbox", "pending_send missing outbox row")
        pkt, dig, status, mac = bytes(row[0]), bytes(row[1]), str(row[2]), bytes(row[3])
        expected = self._mac(
            b"IDRE-V3-STORE-OUTBOX",
            session_id,
            direction.encode("ascii"),
            struct.pack(">I Q", ps.epoch, ps.seq),
            pkt,
            dig,
            status.encode("ascii"),
        )
        if not hmac.compare_digest(mac, expected) or status != "pending":
            raise StateStoreError("corrupt_or_tampered_outbox")
        if not hmac.compare_digest(pkt, ps.packet_bytes):
            raise StateStoreError("inconsistent_outbox", "outbox packet_bytes disagrees with pending_send")
        return pkt

    def list_inbox(self, session_id: bytes, direction: str) -> List[InboxRecordV3]:
        """Return all verified durable inbox records for `(session_id, direction)` in sequence order."""
        rows = self._conn.execute(
            """
            SELECT epoch, seq, packet_digest, plaintext, row_mac
            FROM inbox
            WHERE session_id = ? AND direction = ?
            ORDER BY epoch ASC, seq ASC;
            """,
            (session_id, direction),
        ).fetchall()
        out: List[InboxRecordV3] = []
        for epoch, seq, digest, pt, mac in rows:
            dig_b = bytes(digest)
            expected = self._mac(
                b"IDRE-V3-STORE-INBOX",
                session_id,
                direction.encode("ascii"),
                struct.pack(">I Q", int(epoch), int(seq)),
                dig_b,
                str(pt).encode("utf-8"),
            )
            if not hmac.compare_digest(bytes(mac), expected):
                raise StateStoreError("corrupt_or_tampered_inbox")
            out.append(
                InboxRecordV3(
                    delivery_id=DeliveryIdV3(session_id, direction, int(epoch), int(seq)),
                    packet_digest=dig_b,
                    plaintext=str(pt),
                )
            )
        return out

    def invalidate_all_sessions_after_backup_restore(self) -> int:
        """Close every persisted direction after administrative backup restore.

        Enforces the recovery contract: restored backups MUST establish a fresh
        authenticated session and NEVER resume old key/counter contexts.
        """
        self._conn.execute("BEGIN IMMEDIATE;")
        try:
            rows = self._conn.execute(
                "SELECT session_id, direction FROM direction_states;"
            ).fetchall()
            closed_count = 0
            for sid_raw, direction in rows:
                sid = bytes(sid_raw)
                st = self._get_direction_in_tx(sid, str(direction))
                if not st.closed:
                    self._put_direction_in_tx(sid, replace(st, closed=True))
                    closed_count += 1
            self._conn.execute("COMMIT;")
            return closed_count
        except Exception:
            self._conn.execute("ROLLBACK;")
            raise


def commit_prepared_send(
    store: StateStoreV3,
    prepared: PreparedSendV3,
    *,
    session_id: bytes,
) -> OutboxIdV3:
    """Atomically commit staged pending send state and exact outbox bytes before transmission."""
    direction = prepared.pending_state.direction
    store._conn.execute("BEGIN IMMEDIATE;")
    try:
        current = store._get_direction_in_tx(session_id, direction)
        if current.closed:
            raise StateStoreError("closed_direction")
        if current != prepared.pre_state:
            raise StateStoreError("stale_pre_state", "direction state changed before send commit")
        if current.next_seq >= MAX_UINT64:
            raise StateStoreError("seq_wraparound")

        outbox_mac = store._mac(
            b"IDRE-V3-STORE-OUTBOX",
            session_id,
            direction.encode("ascii"),
            struct.pack(">I Q", prepared.epoch, prepared.seq),
            prepared.packet_bytes,
            prepared.packet_digest,
            b"pending",
        )
        store._conn.execute(
            """
            INSERT INTO outbox(session_id, direction, epoch, seq, packet_bytes, packet_digest, status, row_mac)
            VALUES (?, ?, ?, ?, ?, ?, 'pending', ?);
            """,
            (
                session_id,
                direction,
                prepared.epoch,
                prepared.seq,
                prepared.packet_bytes,
                prepared.packet_digest,
                outbox_mac,
            ),
        )
        store._put_direction_in_tx(session_id, prepared.pending_state)
        store._fire_hook("before_send_commit")
        store._conn.execute("COMMIT;")
    except Exception:
        store._conn.execute("ROLLBACK;")
        raise
    store._fire_hook("after_send_commit")
    return OutboxIdV3(session_id, direction, prepared.epoch, prepared.seq)


def commit_received(
    store: StateStoreV3,
    result: ValidatedReceiveV3,
    *,
    session_id: bytes,
) -> DeliveryIdV3:
    """Atomically commit next direction state + unique durable inbox record (idempotent on duplicate)."""
    direction = result.next_state.direction
    delivery_id = DeliveryIdV3(session_id, direction, result.epoch, result.seq)

    if result.is_duplicate:
        # Duplicate of already-committed packet: verify inbox record exists, perform NO state change
        existing = store._conn.execute(
            "SELECT packet_digest FROM inbox WHERE session_id = ? AND direction = ? AND epoch = ? AND seq = ?;",
            (session_id, direction, result.epoch, result.seq),
        ).fetchone()
        if existing is None or not hmac.compare_digest(bytes(existing[0]), result.packet_digest):
            raise StateStoreError("inconsistent_duplicate_inbox")
        return delivery_id

    store._conn.execute("BEGIN IMMEDIATE;")
    try:
        current = store._get_direction_in_tx(session_id, direction)
        if current.closed:
            raise StateStoreError("closed_direction")
        if current.epoch != result.epoch or current.next_seq != result.seq:
            raise StateStoreError("stale_receive_state")

        inbox_mac = store._mac(
            b"IDRE-V3-STORE-INBOX",
            session_id,
            direction.encode("ascii"),
            struct.pack(">I Q", result.epoch, result.seq),
            result.packet_digest,
            result.plaintext.encode("utf-8"),
        )
        store._conn.execute(
            """
            INSERT INTO inbox(session_id, direction, epoch, seq, packet_digest, plaintext, row_mac)
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            (
                session_id,
                direction,
                result.epoch,
                result.seq,
                result.packet_digest,
                result.plaintext,
                inbox_mac,
            ),
        )
        store._put_direction_in_tx(session_id, result.next_state)
        store._fire_hook("before_receive_commit")
        store._conn.execute("COMMIT;")
    except sqlite3.IntegrityError as exc:
        store._conn.execute("ROLLBACK;")
        raise StateStoreError("duplicate_delivery_id") from exc
    except Exception:
        store._conn.execute("ROLLBACK;")
        raise
    store._fire_hook("after_receive_commit")
    return delivery_id


def apply_ack(
    store: StateStoreV3,
    ack_packet: bytes,
    *,
    session_id: bytes,
    direction: str,
    profile: ProfileV3,
) -> AckResultV3:
    """Validate an authenticated ACK and atomically resolve the pending send transition."""
    store._conn.execute("BEGIN IMMEDIATE;")
    try:
        current = store._get_direction_in_tx(session_id, direction)
        if current.closed:
            raise StateStoreError("closed_direction")
        if current.pending_send is None:
            raise EngineError("no_pending_send")
        ps = current.pending_send
        resolved_state = validate_ack(
            current,
            ack_packet,
            profile=profile,
            session_id=session_id,
        )
        acked_mac = store._mac(
            b"IDRE-V3-STORE-OUTBOX",
            session_id,
            direction.encode("ascii"),
            struct.pack(">I Q", ps.epoch, ps.seq),
            ps.packet_bytes,
            ps.packet_digest,
            b"acked",
        )
        store._conn.execute(
            """
            UPDATE outbox SET status = 'acked', row_mac = ?
            WHERE session_id = ? AND direction = ? AND epoch = ? AND seq = ?;
            """,
            (acked_mac, session_id, direction, ps.epoch, ps.seq),
        )
        store._put_direction_in_tx(session_id, resolved_state)
        store._fire_hook("before_ack_commit")
        store._conn.execute("COMMIT;")
    except Exception:
        store._conn.execute("ROLLBACK;")
        raise
    store._fire_hook("after_ack_commit")
    return AckResultV3(
        resolved=True,
        outbox_id=OutboxIdV3(session_id, direction, ps.epoch, ps.seq),
        new_next_seq=resolved_state.next_seq,
        new_field_age=resolved_state.field.age,
    )
