"""IDRE v3 Field-Dependent Key Schedule and Mutual Handshake (Task 5).

Uses HKDF-SHA-256 (RFC 5869) via `cryptography` in `hive/`.
There is NO optional field parameter and NO ratchet-only DATA key derivation path.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core.field_state_v3 import FieldViewV3, field_view, initialize_field
from core.profile_v3 import (
    DIR_I2R,
    DIR_R2I,
    ROLE_INITIATOR,
    ROLE_RESPONDER,
    VALID_ROLES,
    MessageContextV3,
    ProvisioningBundleV3,
    TranscriptV3,
)
from core.session_v3 import DirectionStateV3, SessionV3


class KeyScheduleError(ValueError):
    """Raised on invalid key-schedule inputs or failed handshake confirmation."""


def _hkdf_sha256(*, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


@dataclass(frozen=True)
class MessageKeysV3:
    """Purpose-separated per-message symmetric keys derived from one pre-message snapshot."""

    body_key: bytes  # 32 bytes (ChaCha20-Poly1305)
    body_nonce: bytes  # 12 bytes
    header_key: bytes  # 32 bytes
    header_nonce: bytes  # 12 bytes
    route_tag: bytes  # 16 bytes
    ack_key: bytes  # 32 bytes
    ack_nonce: bytes  # 12 bytes

    def __repr__(self) -> str:
        return "MessageKeysV3(<redacted>)"


def initialize_session(
    bundle: ProvisioningBundleV3,
    transcript: TranscriptV3,
) -> SessionV3:
    """Derive isolated i2r and r2i directional states from provisioning and transcript."""
    bundle.validate()
    t_bytes = transcript.canonical_bytes()
    transcript_hash = hashlib.sha256(t_bytes).digest()

    if bundle.local_node_id == transcript.initiator_id:
        role = ROLE_INITIATOR
        peer_id = transcript.responder_id
    elif bundle.local_node_id == transcript.responder_id:
        role = ROLE_RESPONDER
        peer_id = transcript.initiator_id
    else:
        raise KeyScheduleError("bundle.local_node_id does not match transcript endpoints")

    session_root = _hkdf_sha256(
        ikm=bytes(bundle.network_secret),
        salt=transcript_hash,
        info=b"IDRE-V3-SESSION-ROOT",
        length=32,
    )

    dirs: dict[str, DirectionStateV3] = {}
    for d in (DIR_I2R, DIR_R2I):
        d_bytes = d.encode("ascii")
        chain_secret = _hkdf_sha256(
            ikm=session_root,
            salt=transcript_hash,
            info=b"IDRE-V3-CHAIN-INIT|" + d_bytes,
            length=32,
        )
        field_seed = _hkdf_sha256(
            ikm=bytes(bundle.field_init_secret),
            salt=transcript_hash,
            info=b"IDRE-V3-FIELD-SEED|" + d_bytes,
            length=32,
        )
        dict_key = _hkdf_sha256(
            ikm=session_root,
            salt=transcript_hash,
            info=b"IDRE-V3-DICT-KEY|" + d_bytes,
            length=32,
        )
        field_state = initialize_field(
            bundle.profile,
            field_seed,
            b"dir:" + d_bytes + b":" + transcript_hash,
        )
        dirs[d] = DirectionStateV3(
            direction=d,
            field=field_state,
            chain_secret=chain_secret,
            dict_key=dict_key,
            epoch=1,
            next_seq=0,
        )

    tx = dirs[DIR_I2R] if role == ROLE_INITIATOR else dirs[DIR_R2I]
    rx = dirs[DIR_R2I] if role == ROLE_INITIATOR else dirs[DIR_I2R]

    return SessionV3(
        profile=bundle.profile,
        session_id=transcript.session_id,
        local_node_id=bundle.local_node_id,
        peer_node_id=peer_id,
        role=role,
        transcript_hash=transcript_hash,
        tx=tx,
        rx=rx,
    )


def _handshake_confirm_tag(
    bundle: ProvisioningBundleV3,
    session: SessionV3,
    *,
    role: str,
) -> bytes:
    if role not in VALID_ROLES:
        raise KeyScheduleError(f"invalid role: {role!r}")
    i2r_state = session.tx if session.tx.direction == DIR_I2R else session.rx
    r2i_state = session.rx if session.rx.direction == DIR_R2I else session.tx
    v_i2r = field_view(i2r_state.field, session.profile)
    v_r2i = field_view(r2i_state.field, session.profile)

    confirm_key = _hkdf_sha256(
        ikm=bytes(bundle.network_secret) + bytes(bundle.field_init_secret),
        salt=session.transcript_hash,
        info=b"IDRE-V3-HANDSHAKE-CONFIRM-KEY",
        length=32,
    )
    msg = (
        b"IDRE-V3-CONFIRM|"
        + role.encode("ascii")
        + b"|"
        + session.transcript_hash
        + v_i2r.binding_bytes
        + v_r2i.binding_bytes
    )
    return hmac.new(confirm_key, msg, hashlib.sha256).digest()


def compute_handshake_confirm(bundle: ProvisioningBundleV3, session: SessionV3) -> bytes:
    """Compute local role's mutual handshake confirmation tag."""
    return _handshake_confirm_tag(bundle, session, role=session.role)


def verify_handshake_confirm(
    bundle: ProvisioningBundleV3,
    session: SessionV3,
    peer_tag: bytes,
) -> bool:
    """Verify peer's mutual handshake confirmation tag (rejects reflection/substitution)."""
    if not isinstance(peer_tag, (bytes, bytearray)) or len(peer_tag) != 32:
        return False
    peer_role = ROLE_RESPONDER if session.role == ROLE_INITIATOR else ROLE_INITIATOR
    expected = _handshake_confirm_tag(bundle, session, role=peer_role)
    return hmac.compare_digest(expected, bytes(peer_tag))


def establish_confirmed_session(
    bundle: ProvisioningBundleV3,
    transcript: TranscriptV3,
    *,
    peer_confirm_tag: bytes,
) -> SessionV3:
    """Atomically initialize and confirm a live v3 session; raises without committing on failure."""
    candidate = initialize_session(bundle, transcript)
    if not verify_handshake_confirm(bundle, candidate, peer_confirm_tag):
        raise KeyScheduleError("handshake_confirmation_failed")
    return candidate


def derive_message_keys(
    view: FieldViewV3,
    chain_secret: bytes,
    context: MessageContextV3,
) -> MessageKeysV3:
    """Derive purpose-separated body, header, route_tag, and ACK keys from current field + chain.

    `view` is mandatory; there is no ratchet-only DATA key path.
    """
    if not isinstance(view, FieldViewV3) or len(view.binding_bytes) != 32:
        raise KeyScheduleError("valid FieldViewV3 is mandatory for derive_message_keys")
    if not isinstance(chain_secret, (bytes, bytearray)) or len(chain_secret) != 32:
        raise KeyScheduleError("chain_secret must be 32 bytes")
    if not isinstance(context, MessageContextV3):
        raise KeyScheduleError("context must be MessageContextV3")

    ctx_bytes = context.canonical_bytes()
    ctx_salt = hashlib.sha256(ctx_bytes).digest()
    ikm = bytes(chain_secret) + view.binding_bytes

    msg_master = _hkdf_sha256(
        ikm=ikm,
        salt=ctx_salt,
        info=b"IDRE-V3-MSG-MASTER",
        length=32,
    )
    body_mat = _hkdf_sha256(
        ikm=msg_master,
        salt=ctx_salt,
        info=b"IDRE-V3-KEY-BODY",
        length=44,
    )
    hdr_mat = _hkdf_sha256(
        ikm=msg_master,
        salt=ctx_salt,
        info=b"IDRE-V3-KEY-HEADER",
        length=60,
    )
    ack_mat = _hkdf_sha256(
        ikm=msg_master,
        salt=ctx_salt,
        info=b"IDRE-V3-KEY-ACK",
        length=44,
    )
    return MessageKeysV3(
        body_key=body_mat[:32],
        body_nonce=body_mat[32:44],
        header_key=hdr_mat[:32],
        header_nonce=hdr_mat[32:44],
        route_tag=hdr_mat[44:60],
        ack_key=ack_mat[:32],
        ack_nonce=ack_mat[32:44],
    )


def advance_chain_secret(
    chain_secret: bytes,
    view: FieldViewV3,
    context: MessageContextV3,
) -> bytes:
    """Derive next 32-byte directional chain secret bound to current field and context."""
    if not isinstance(view, FieldViewV3) or len(view.binding_bytes) != 32:
        raise KeyScheduleError("valid FieldViewV3 is mandatory for advance_chain_secret")
    if not isinstance(chain_secret, (bytes, bytearray)) or len(chain_secret) != 32:
        raise KeyScheduleError("chain_secret must be 32 bytes")
    ctx_salt = hashlib.sha256(context.canonical_bytes()).digest()
    return _hkdf_sha256(
        ikm=bytes(chain_secret) + view.binding_bytes,
        salt=ctx_salt,
        info=b"IDRE-V3-CHAIN-NEXT",
        length=32,
    )
