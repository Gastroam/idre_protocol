"""IDRE v3 Isolated Directional Session State (Task 4).

Each session has completely separate mutable/staged state for transmit (`tx`)
and receive (`rx`) directions:
- Separate canonical `FieldStateV3`
- Separate 32-byte `chain_secret`
- Separate 32-byte stable directional `dict_key`
- Separate `epoch`, `next_seq`, `last_accepted`, and `pending_send`

All state objects are frozen dataclasses so candidate transitions can be staged
and discarded without ever mutating live state. Local telemetry (timestamps,
caches, object IDs) is excluded from canonical serialization and equality.

Core dependency rule: Python standard library only.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, replace
from typing import Optional

from core.codec_v3 import DictStateV3, decode_dict_state_v3, encode_dict_state_v3
from core.field_state_v3 import FieldStateV3, decode_field, encode_field
from core.profile_v3 import (
    BYTE_TO_DIRECTION,
    DIRECTION_TO_BYTE,
    MAX_UINT32,
    MAX_UINT64,
    SESSION_ID_BYTES,
    VALID_ROLES,
    ProfileV3,
)

DIRECTION_STATE_MAGIC = b"IDRD3\x00"


class SessionStateError(ValueError):
    """Raised on invalid directional or session state invariants."""


def _lp(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def _read_lp(buf: bytes, off: int) -> tuple[bytes, int]:
    if off + 4 > len(buf):
        raise SessionStateError("truncated length-prefixed field")
    (n,) = struct.unpack(">I", buf[off : off + 4])
    off += 4
    if off + n > len(buf):
        raise SessionStateError("truncated payload in length-prefixed field")
    return buf[off : off + n], off + n


@dataclass(frozen=True)
class PendingSendV3:
    """In-flight stop-and-wait DATA packet awaiting authenticated ACK."""

    epoch: int
    seq: int
    packet_bytes: bytes
    packet_digest: bytes  # 32-byte SHA-256 of packet_bytes
    expected_ack_key: bytes  # 32 bytes
    expected_ack_nonce: bytes  # 12 bytes
    candidate_field: FieldStateV3
    candidate_chain_secret: bytes  # 32 bytes
    candidate_next_seq: int
    candidate_dict_state: DictStateV3 = DictStateV3()

    def __post_init__(self) -> None:
        if not (0 <= self.epoch <= MAX_UINT32):
            raise SessionStateError("pending epoch out of uint32 range")
        if not (0 <= self.seq <= MAX_UINT64):
            raise SessionStateError("pending seq out of uint64 range")
        if not self.packet_bytes:
            raise SessionStateError("pending packet_bytes must not be empty")
        if len(self.packet_digest) != 32:
            raise SessionStateError("pending packet_digest must be 32 bytes")
        if len(self.expected_ack_key) != 32:
            raise SessionStateError("pending expected_ack_key must be 32 bytes")
        if len(self.expected_ack_nonce) != 12:
            raise SessionStateError("pending expected_ack_nonce must be 12 bytes")
        if len(self.candidate_chain_secret) != 32:
            raise SessionStateError("pending candidate_chain_secret must be 32 bytes")
        if not (0 <= self.candidate_next_seq <= MAX_UINT64):
            raise SessionStateError("pending candidate_next_seq out of uint64 range")


@dataclass(frozen=True)
class AcceptedRecordV3:
    """Last accepted packet identity and cached idempotent ACK for a receive direction."""

    epoch: int
    seq: int
    packet_digest: bytes  # 32-byte SHA-256
    ack_packet_bytes: bytes

    def __post_init__(self) -> None:
        if not (0 <= self.epoch <= MAX_UINT32):
            raise SessionStateError("accepted epoch out of uint32 range")
        if not (0 <= self.seq <= MAX_UINT64):
            raise SessionStateError("accepted seq out of uint64 range")
        if len(self.packet_digest) != 32:
            raise SessionStateError("accepted packet_digest must be 32 bytes")
        if not self.ack_packet_bytes:
            raise SessionStateError("accepted ack_packet_bytes must not be empty")


@dataclass(frozen=True)
class DirectionStateV3:
    """Complete canonical state for one direction (`i2r` or `r2i`) of a v3 session."""

    direction: str
    field: FieldStateV3
    chain_secret: bytes  # 32 bytes
    dict_key: bytes  # 32 bytes (stable directional session dictionary key)
    epoch: int = 1
    next_seq: int = 0
    closed: bool = False
    last_accepted: Optional[AcceptedRecordV3] = None
    pending_send: Optional[PendingSendV3] = None
    dict_state: DictStateV3 = DictStateV3()
    last_epoch_hash: bytes = b""

    def __post_init__(self) -> None:
        if self.direction not in DIRECTION_TO_BYTE:
            raise SessionStateError(f"invalid direction: {self.direction!r}")
        if not isinstance(self.field, FieldStateV3):
            raise SessionStateError("field must be FieldStateV3")
        if len(self.chain_secret) != 32:
            raise SessionStateError("chain_secret must be 32 bytes")
        if len(self.dict_key) != 32:
            raise SessionStateError("dict_key must be 32 bytes")
        if not (0 <= self.epoch <= MAX_UINT32):
            raise SessionStateError("epoch out of uint32 range")
        if not (0 <= self.next_seq <= MAX_UINT64):
            raise SessionStateError("next_seq out of uint64 range")


@dataclass(frozen=True)
class SessionV3:
    """Full v3 session with strictly isolated transmit and receive directional states."""

    profile: ProfileV3
    session_id: bytes
    local_node_id: str
    peer_node_id: str
    role: str
    transcript_hash: bytes
    tx: DirectionStateV3
    rx: DirectionStateV3

    def __post_init__(self) -> None:
        if len(self.session_id) != SESSION_ID_BYTES:
            raise SessionStateError(f"session_id must be {SESSION_ID_BYTES} bytes")
        if self.role not in VALID_ROLES:
            raise SessionStateError(f"invalid role: {self.role!r}")
        if len(self.transcript_hash) != 32:
            raise SessionStateError("transcript_hash must be 32 bytes")
        if self.tx.direction == self.rx.direction:
            raise SessionStateError("tx and rx must have opposite directions")

    def with_tx(self, new_tx: DirectionStateV3) -> "SessionV3":
        if new_tx.direction != self.tx.direction:
            raise SessionStateError("tx direction mismatch")
        return replace(self, tx=new_tx)

    def with_rx(self, new_rx: DirectionStateV3) -> "SessionV3":
        if new_rx.direction != self.rx.direction:
            raise SessionStateError("rx direction mismatch")
        return replace(self, rx=new_rx)


@dataclass(frozen=True)
class PreparedSendV3:
    """Output of pure `prepare_send`: exact packet bytes + staged transitions."""

    packet_bytes: bytes
    packet_digest: bytes
    epoch: int
    seq: int
    pre_state: DirectionStateV3
    pending_state: DirectionStateV3
    candidate_next_state: DirectionStateV3


@dataclass(frozen=True)
class ValidatedReceiveV3:
    """Output of pure `validate_receive`: decoded plaintext + ACK + staged next state."""

    plaintext: str
    packet_digest: bytes
    epoch: int
    seq: int
    ack_packet_bytes: bytes
    next_state: DirectionStateV3
    is_duplicate: bool = False


def encode_direction_state(state: DirectionStateV3) -> bytes:
    """Authoritative canonical serialization of `DirectionStateV3` (excludes telemetry)."""
    out = bytearray()
    out.extend(DIRECTION_STATE_MAGIC)
    flags = (
        (0x01 if state.closed else 0)
        | (0x02 if state.last_accepted is not None else 0)
        | (0x04 if state.pending_send is not None else 0)
        | (0x08 if (state.dict_state.entries or state.dict_state.obs_counts) else 0)
        | (0x10 if state.last_epoch_hash else 0)
    )
    out.extend(
        struct.pack(
            ">B B I Q",
            DIRECTION_TO_BYTE[state.direction],
            flags,
            state.epoch,
            state.next_seq,
        )
    )
    out.extend(state.chain_secret)
    out.extend(state.dict_key)
    out.extend(_lp(encode_field(state.field)))

    if state.last_accepted is not None:
        la = state.last_accepted
        out.extend(struct.pack(">I Q", la.epoch, la.seq))
        out.extend(la.packet_digest)
        out.extend(_lp(la.ack_packet_bytes))

    if state.pending_send is not None:
        ps = state.pending_send
        out.extend(struct.pack(">I Q Q", ps.epoch, ps.seq, ps.candidate_next_seq))
        out.extend(ps.packet_digest)
        out.extend(ps.expected_ack_key)
        out.extend(ps.expected_ack_nonce)
        out.extend(ps.candidate_chain_secret)
        out.extend(_lp(ps.packet_bytes))
        out.extend(_lp(encode_field(ps.candidate_field)))
        out.extend(_lp(encode_dict_state_v3(ps.candidate_dict_state)))

    if flags & 0x08:
        out.extend(_lp(encode_dict_state_v3(state.dict_state)))

    if flags & 0x10:
        out.extend(_lp(state.last_epoch_hash))

    return bytes(out)


def decode_direction_state(raw: bytes) -> DirectionStateV3:
    """Strictly decode canonical `DirectionStateV3` bytes."""
    bb = bytes(raw)
    hdr = len(DIRECTION_STATE_MAGIC) + 1 + 1 + 4 + 8 + 32 + 32
    if len(bb) < hdr:
        raise SessionStateError("truncated DirectionStateV3")
    if bb[: len(DIRECTION_STATE_MAGIC)] != DIRECTION_STATE_MAGIC:
        raise SessionStateError("bad DirectionStateV3 magic")
    off = len(DIRECTION_STATE_MAGIC)
    dir_b, flags, epoch, next_seq = struct.unpack(">B B I Q", bb[off : off + 14])
    off += 14
    if dir_b not in BYTE_TO_DIRECTION:
        raise SessionStateError(f"invalid direction byte: {dir_b}")
    if flags & ~0x1F:
        raise SessionStateError(f"invalid flags byte: {flags}")
    chain_secret = bb[off : off + 32]
    off += 32
    dict_key = bb[off : off + 32]
    off += 32
    field_bytes, off = _read_lp(bb, off)
    field_state = decode_field(field_bytes)

    last_accepted: Optional[AcceptedRecordV3] = None
    if flags & 0x02:
        if off + 12 + 32 > len(bb):
            raise SessionStateError("truncated last_accepted record")
        la_epoch, la_seq = struct.unpack(">I Q", bb[off : off + 12])
        off += 12
        la_digest = bb[off : off + 32]
        off += 32
        la_ack, off = _read_lp(bb, off)
        last_accepted = AcceptedRecordV3(
            epoch=la_epoch,
            seq=la_seq,
            packet_digest=la_digest,
            ack_packet_bytes=la_ack,
        )

    pending_send: Optional[PendingSendV3] = None
    if flags & 0x04:
        if off + 20 + 32 + 32 + 12 + 32 > len(bb):
            raise SessionStateError("truncated pending_send record")
        ps_epoch, ps_seq, ps_cand_seq = struct.unpack(">I Q Q", bb[off : off + 20])
        off += 20
        ps_digest = bb[off : off + 32]
        off += 32
        ps_ack_key = bb[off : off + 32]
        off += 32
        ps_ack_nonce = bb[off : off + 12]
        off += 12
        ps_cand_chain = bb[off : off + 32]
        off += 32
        ps_pkt, off = _read_lp(bb, off)
        ps_cand_field_bytes, off = _read_lp(bb, off)
        ps_cand_dict_bytes, off = _read_lp(bb, off)
        pending_send = PendingSendV3(
            epoch=ps_epoch,
            seq=ps_seq,
            packet_bytes=ps_pkt,
            packet_digest=ps_digest,
            expected_ack_key=ps_ack_key,
            expected_ack_nonce=ps_ack_nonce,
            candidate_field=decode_field(ps_cand_field_bytes),
            candidate_chain_secret=ps_cand_chain,
            candidate_next_seq=ps_cand_seq,
            candidate_dict_state=decode_dict_state_v3(ps_cand_dict_bytes),
        )

    dict_state = DictStateV3()
    if flags & 0x08:
        ds_bytes, off = _read_lp(bb, off)
        dict_state = decode_dict_state_v3(ds_bytes)

    last_epoch_hash = b""
    if flags & 0x10:
        last_epoch_hash, off = _read_lp(bb, off)

    if off != len(bb):
        raise SessionStateError("trailing bytes in DirectionStateV3")

    return DirectionStateV3(
        direction=BYTE_TO_DIRECTION[dir_b],
        field=field_state,
        chain_secret=chain_secret,
        dict_key=dict_key,
        epoch=epoch,
        next_seq=next_seq,
        closed=bool(flags & 0x01),
        last_accepted=last_accepted,
        pending_send=pending_send,
        dict_state=dict_state,
        last_epoch_hash=last_epoch_hash,
    )
