"""IDRE v3 Pure Atomic DATA Engine (Task 6).

Provides pure `prepare_send`, `validate_receive`, and `validate_ack`:
- Every DATA packet binds its AEAD body key (and optional header key/route tag)
  to the immutable pre-message `FieldViewV3` + directional `chain_secret`.
- All validation (outer framing, AEAD auth, inner codec stream, strict vocab)
  completes before returning a staged candidate `DirectionStateV3`.
- Rejected inputs NEVER mutate authoritative state and NEVER release unauthenticated plaintext.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import replace

from core.codec_v3 import CodecV3Error, pack_strict_stream_v3, unpack_strict_stream_v3
from core.field_state_v3 import AcceptedEventV3, advance_field, field_view
from core.profile_v3 import (
    DIR_I2R,
    FLAG_ENCRYPTED_HEADER,
    MAX_UINT64,
    MSG_TYPE_ACK,
    MSG_TYPE_DATA,
    ROLE_INITIATOR,
    ROLE_RESPONDER,
    MessageContextV3,
    ProfileV3,
    validate_profile,
)
from core.session_v3 import (
    AcceptedRecordV3,
    DirectionStateV3,
    PendingSendV3,
    PreparedSendV3,
    SessionV3,
    ValidatedReceiveV3,
)
from core.vocab_codec import Vocab
from core.vocab_v3 import VocabManifestError, decode_strict_v3, encode_strict_v3
from hive.crypto_v3 import (
    CryptoV3Error,
    aead_open,
    aead_seal,
    open_encrypted_header_v3,
    pack_frame_v3,
    parse_frame_v3,
    seal_encrypted_header_v3,
)
from hive.key_schedule_v3 import advance_chain_secret, derive_message_keys

_ACK_PAYLOAD_STRUCT = struct.Struct(">16s B I Q 32s")


class EngineError(ValueError):
    """Typed, plaintext-free failure raised by pure v3 engine operations."""

    def __init__(self, reason: str, message: str = "") -> None:
        self.reason = reason
        super().__init__(message or reason)


def direction_message_context(
    session: SessionV3,
    *,
    direction: str,
    epoch: int,
    seq: int,
    msg_type: int = MSG_TYPE_DATA,
) -> MessageContextV3:
    """Build the canonical MessageContextV3 shared by sender and receiver for a direction."""
    if direction == session.tx.direction:
        sender_role = session.role
        receiver_id = session.peer_node_id
    elif direction == session.rx.direction:
        sender_role = ROLE_RESPONDER if session.role == ROLE_INITIATOR else ROLE_INITIATOR
        receiver_id = session.local_node_id
    else:
        raise EngineError("invalid_direction", f"unknown direction {direction!r}")

    return MessageContextV3(
        protocol_version=session.profile.protocol_version,
        bundle_id=session.profile.bundle_id,
        session_id=session.session_id,
        role=sender_role,
        peer_id=receiver_id,
        direction=direction,
        epoch=epoch,
        seq=seq,
        msg_type=msg_type,
    )


def _build_ack_packet(
    *,
    profile: ProfileV3,
    session_id: bytes,
    direction: str,
    epoch: int,
    seq: int,
    packet_digest: bytes,
    ack_key: bytes,
    ack_nonce: bytes,
) -> bytes:
    dir_b = 0x00 if direction == DIR_I2R else 0x01
    ack_pt = _ACK_PAYLOAD_STRUCT.pack(session_id, dir_b, epoch, seq, packet_digest)
    # Construct outer ACK header first (length = len(ack_pt) + 16)
    dummy_ct = b"\x00" * (len(ack_pt) + 16)
    probe_frame = pack_frame_v3(
        msg_type=MSG_TYPE_ACK,
        flags=0,
        direction=direction,
        bundle_id=profile.bundle_id,
        session_id=session_id,
        epoch=epoch,
        seq=seq,
        body_bytes=dummy_ct,
        max_wire_cell_bytes=profile.max_wire_cell_bytes,
    )
    outer_hdr = probe_frame[:54]
    ct = aead_seal(ack_key, ack_nonce, ack_pt, b"IDRE-V3-ACK|" + outer_hdr)
    return outer_hdr + ct


def prepare_send(
    state: DirectionStateV3,
    content: str,
    context: MessageContextV3,
    *,
    profile: ProfileV3,
    vocab: Vocab,
) -> PreparedSendV3:
    """Pure preparation of a strict v3 DATA packet and staged directional transitions."""
    validate_profile(profile, vocab)
    if state.closed:
        raise EngineError("closed_direction")
    if state.pending_send is not None:
        raise EngineError("pending_in_flight")
    if state.next_seq >= MAX_UINT64:
        raise EngineError("seq_wraparound")
    if context.direction != state.direction:
        raise EngineError("direction_mismatch")
    if context.epoch != state.epoch:
        raise EngineError("epoch_mismatch")
    if context.seq != state.next_seq:
        raise EngineError("seq_mismatch")
    if context.msg_type != MSG_TYPE_DATA:
        raise EngineError("bad_msg_type")

    # 1. Strict vocabulary encoding & capacity check BEFORE any transition
    try:
        vocab_blob = encode_strict_v3(
            content, vocab, max_plaintext_bytes=profile.max_plaintext_bytes
        )
        inner_stream = pack_strict_stream_v3(
            vocab_blob, max_plaintext_bytes=profile.max_plaintext_bytes
        )
    except (VocabManifestError, CodecV3Error) as exc:
        reason = getattr(exc, "reason", "strict_vocab_encode_failed")
        raise EngineError(reason, str(exc)) from exc

    # 2. Pre-message immutable snapshot -> derive body, header, and ACK keys together
    view = field_view(state.field, profile)
    keys = derive_message_keys(view, state.chain_secret, context)

    flags = FLAG_ENCRYPTED_HEADER if profile.encrypted_headers else 0
    body_ct_len = len(inner_stream) + 16
    total_body_len = body_ct_len + (80 if profile.encrypted_headers else 0)

    try:
        probe = pack_frame_v3(
            msg_type=MSG_TYPE_DATA,
            flags=flags,
            direction=state.direction,
            bundle_id=profile.bundle_id,
            session_id=context.session_id,
            epoch=state.epoch,
            seq=state.next_seq,
            body_bytes=b"\x00" * total_body_len,
            max_wire_cell_bytes=profile.max_wire_cell_bytes,
        )
        outer_hdr = probe[:54]
        body_ct = aead_seal(keys.body_key, keys.body_nonce, inner_stream, outer_hdr)
        if profile.encrypted_headers:
            enc_hdr_prefix = seal_encrypted_header_v3(
                header_key=keys.header_key,
                header_nonce=keys.header_nonce,
                route_tag=keys.route_tag,
                bundle_id=profile.bundle_id,
                session_id=context.session_id,
                epoch=state.epoch,
                seq=state.next_seq,
                direction=state.direction,
                msg_type=MSG_TYPE_DATA,
                outer_header_aad=outer_hdr,
            )
            packet_bytes = outer_hdr + enc_hdr_prefix + body_ct
        else:
            packet_bytes = outer_hdr + body_ct
    except CryptoV3Error as exc:
        raise EngineError(exc.reason, str(exc)) from exc

    packet_digest = hashlib.sha256(packet_bytes).digest()

    # 3. Stage candidate next state (committed only after authenticated ACK)
    event = AcceptedEventV3(
        event_type="data_accepted",
        seq=state.next_seq,
        epoch=state.epoch,
        token_digest=hashlib.sha256(vocab_blob).digest(),
    )
    cand_field = advance_field(state.field, event)
    cand_chain = advance_chain_secret(state.chain_secret, view, context)
    cand_next_seq = state.next_seq + 1

    pending = PendingSendV3(
        epoch=state.epoch,
        seq=state.next_seq,
        packet_bytes=packet_bytes,
        packet_digest=packet_digest,
        expected_ack_key=keys.ack_key,
        expected_ack_nonce=keys.ack_nonce,
        candidate_field=cand_field,
        candidate_chain_secret=cand_chain,
        candidate_next_seq=cand_next_seq,
    )
    pending_state = replace(state, pending_send=pending)
    candidate_next_state = replace(
        state,
        field=cand_field,
        chain_secret=cand_chain,
        next_seq=cand_next_seq,
        pending_send=None,
    )
    return PreparedSendV3(
        packet_bytes=packet_bytes,
        packet_digest=packet_digest,
        epoch=state.epoch,
        seq=state.next_seq,
        pre_state=state,
        pending_state=pending_state,
        candidate_next_state=candidate_next_state,
    )


def validate_receive(
    state: DirectionStateV3,
    packet: bytes,
    context: MessageContextV3,
    *,
    profile: ProfileV3,
    vocab: Vocab,
) -> ValidatedReceiveV3:
    """Pure, atomic validation of an incoming v3 DATA packet.

    Any authentication, header, codec, or vocabulary failure raises `EngineError`
    without modifying `state` and without releasing unauthenticated plaintext.
    """
    validate_profile(profile, vocab)
    if state.closed:
        raise EngineError("closed_direction")

    try:
        frame = parse_frame_v3(packet, max_wire_cell_bytes=profile.max_wire_cell_bytes)
    except CryptoV3Error as exc:
        raise EngineError(exc.reason, str(exc)) from exc

    if frame.msg_type != MSG_TYPE_DATA:
        raise EngineError("bad_msg_type")
    if frame.bundle_id != profile.bundle_id:
        raise EngineError("bundle_mismatch")
    if frame.session_id != context.session_id:
        raise EngineError("session_mismatch")
    if frame.direction != state.direction or context.direction != state.direction:
        raise EngineError("direction_mismatch")

    expected_flags = FLAG_ENCRYPTED_HEADER if profile.encrypted_headers else 0
    if frame.flags != expected_flags:
        raise EngineError("flags_mismatch")

    packet_digest = hashlib.sha256(bytes(packet)).digest()

    # Exact idempotent duplicate handling (do NOT re-decrypt against advanced field)
    if (
        state.last_accepted is not None
        and frame.epoch == state.last_accepted.epoch
        and frame.seq == state.last_accepted.seq
    ):
        if hmac.compare_digest(packet_digest, state.last_accepted.packet_digest):
            return ValidatedReceiveV3(
                plaintext="",
                packet_digest=packet_digest,
                epoch=frame.epoch,
                seq=frame.seq,
                ack_packet_bytes=state.last_accepted.ack_packet_bytes,
                next_state=state,
                is_duplicate=True,
            )
        raise EngineError("conflicting_duplicate_seq")

    if frame.epoch != state.epoch or context.epoch != state.epoch:
        raise EngineError("epoch_mismatch")
    if frame.seq != state.next_seq or context.seq != state.next_seq:
        raise EngineError("seq_mismatch")

    # Pre-message immutable snapshot -> derive keys from current field + chain
    view = field_view(state.field, profile)
    keys = derive_message_keys(view, state.chain_secret, context)

    try:
        body_ct = frame.body_bytes
        if profile.encrypted_headers:
            body_ct = open_encrypted_header_v3(
                header_key=keys.header_key,
                header_nonce=keys.header_nonce,
                expected_route_tag=keys.route_tag,
                blob=body_ct,
                outer_frame=frame,
            )
        inner_stream = aead_open(keys.body_key, keys.body_nonce, body_ct, frame.header_bytes)
    except CryptoV3Error as exc:
        raise EngineError(exc.reason, str(exc)) from exc

    # Full inner stream and strict vocabulary validation BEFORE advancing candidate state
    try:
        vocab_blob = unpack_strict_stream_v3(
            inner_stream, max_plaintext_bytes=profile.max_plaintext_bytes
        )
        plaintext = decode_strict_v3(
            vocab_blob, vocab, max_plaintext_bytes=profile.max_plaintext_bytes
        )
    except CodecV3Error as exc:
        raise EngineError(exc.reason) from exc
    except VocabManifestError as exc:
        msg = str(exc)
        if "wrong_vocab" in msg:
            reason = "wrong_vocab"
        elif "literal_disallowed" in msg:
            reason = "literal_disallowed"
        elif "oversize" in msg:
            reason = "oversize_payload"
        else:
            reason = "invalid_vocab_payload"
        raise EngineError(reason) from exc

    # Build authenticated control ACK (does NOT train the DATA field)
    ack_packet = _build_ack_packet(
        profile=profile,
        session_id=frame.session_id,
        direction=state.direction,
        epoch=frame.epoch,
        seq=frame.seq,
        packet_digest=packet_digest,
        ack_key=keys.ack_key,
        ack_nonce=keys.ack_nonce,
    )

    event = AcceptedEventV3(
        event_type="data_accepted",
        seq=frame.seq,
        epoch=frame.epoch,
        token_digest=hashlib.sha256(vocab_blob).digest(),
    )
    next_field = advance_field(state.field, event)
    next_chain = advance_chain_secret(state.chain_secret, view, context)
    next_state = replace(
        state,
        field=next_field,
        chain_secret=next_chain,
        next_seq=state.next_seq + 1,
        last_accepted=AcceptedRecordV3(
            epoch=frame.epoch,
            seq=frame.seq,
            packet_digest=packet_digest,
            ack_packet_bytes=ack_packet,
        ),
    )
    return ValidatedReceiveV3(
        plaintext=plaintext,
        packet_digest=packet_digest,
        epoch=frame.epoch,
        seq=frame.seq,
        ack_packet_bytes=ack_packet,
        next_state=next_state,
        is_duplicate=False,
    )


def validate_ack(
    state: DirectionStateV3,
    ack_packet: bytes,
    *,
    profile: ProfileV3,
    session_id: bytes,
) -> DirectionStateV3:
    """Pure validation of an authenticated control ACK; resolves pending send without extra learning."""
    if state.pending_send is None:
        raise EngineError("no_pending_send")
    ps = state.pending_send

    try:
        frame = parse_frame_v3(ack_packet, max_wire_cell_bytes=profile.max_wire_cell_bytes)
    except CryptoV3Error as exc:
        raise EngineError(exc.reason, str(exc)) from exc

    if frame.msg_type != MSG_TYPE_ACK:
        raise EngineError("bad_msg_type")
    if frame.bundle_id != profile.bundle_id or frame.session_id != session_id:
        raise EngineError("ack_identity_mismatch")
    if frame.direction != state.direction or frame.epoch != ps.epoch or frame.seq != ps.seq:
        raise EngineError("ack_sequence_mismatch")

    try:
        ack_pt = aead_open(
            ps.expected_ack_key,
            ps.expected_ack_nonce,
            frame.body_bytes,
            b"IDRE-V3-ACK|" + frame.header_bytes,
        )
    except CryptoV3Error as exc:
        raise EngineError("invalid_ack_mac") from exc

    if len(ack_pt) != _ACK_PAYLOAD_STRUCT.size:
        raise EngineError("malformed_ack_payload")
    sid, dir_b, epoch, seq, digest = _ACK_PAYLOAD_STRUCT.unpack(ack_pt)
    expected_dir_b = 0x00 if state.direction == DIR_I2R else 0x01
    if (
        sid != session_id
        or dir_b != expected_dir_b
        or epoch != ps.epoch
        or seq != ps.seq
        or not hmac.compare_digest(digest, ps.packet_digest)
    ):
        raise EngineError("ack_binding_mismatch")

    return replace(
        state,
        field=ps.candidate_field,
        chain_secret=ps.candidate_chain_secret,
        next_seq=ps.candidate_next_seq,
        pending_send=None,
    )
