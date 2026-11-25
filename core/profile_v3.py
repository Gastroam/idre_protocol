"""IDRE v3 Profile, Provisioning Bundle, Transcript, and Message Context contracts.

Core dependency rule: standard library only (plus NumPy where needed in core/).
Transport cryptography belongs in `hive/`, never in `core/`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from core.vocab_codec import Vocab

# --- Frozen Protocol & Wire Constants (Task 1) ---

PROTOCOL_VERSION_V3 = "IDRE/3.0"
WIRE_MAGIC_V3 = b"IDR3"
WIRE_VERSION_BYTE_V3 = 0x03

MSG_TYPE_HANDSHAKE_INIT = 0x01
MSG_TYPE_HANDSHAKE_RESP = 0x02
MSG_TYPE_DATA = 0x03
MSG_TYPE_ACK = 0x04
MSG_TYPE_EPOCH_CTRL = 0x05

VALID_MSG_TYPES = frozenset(
    {
        MSG_TYPE_HANDSHAKE_INIT,
        MSG_TYPE_HANDSHAKE_RESP,
        MSG_TYPE_DATA,
        MSG_TYPE_ACK,
        MSG_TYPE_EPOCH_CTRL,
    }
)

FLAG_ENCRYPTED_HEADER = 0x01
FLAG_ADAPTIVE_CODEC = 0x02
VALID_FLAGS_MASK = FLAG_ENCRYPTED_HEADER | FLAG_ADAPTIVE_CODEC

ROLE_INITIATOR = "initiator"
ROLE_RESPONDER = "responder"
VALID_ROLES = frozenset({ROLE_INITIATOR, ROLE_RESPONDER})

DIR_I2R = "i2r"
DIR_R2I = "r2i"
DIRECTION_TO_BYTE = {DIR_I2R: 0x00, DIR_R2I: 0x01}
BYTE_TO_DIRECTION = {0x00: DIR_I2R, 0x01: DIR_R2I}

BUNDLE_ID_BYTES = 16
SESSION_ID_BYTES = 16
HANDSHAKE_NONCE_BYTES = 32
VOCAB_DIGEST_BYTES = 32
MIN_SECRET_BYTES = 32

MAX_WIRE_CELL_BYTES = 4096
WIRE_HEADER_BYTES = 54  # 4 magic + 1 ver + 1 type + 1 flags + 1 dir + 16 bundle + 16 sid + 4 epoch + 8 seq + 2 ct_len
AEAD_TAG_BYTES = 16  # ChaCha20-Poly1305 tag
CODEC_FRAMING_OVERHEAD_BYTES = 3  # 1B OP_LITERAL + 2B uint16 len
ENCRYPTED_HEADER_OVERHEAD_BYTES = 80  # 16B route tag + 48B enc header + 16B tag

MAX_UINT32 = 0xFFFFFFFF
MAX_UINT64 = 0xFFFFFFFFFFFFFFFF

ALLOWED_SUITES = frozenset({"HKDF-SHA256+CHACHA20-POLY1305"})
ALLOWED_STATE_SCOPES = frozenset({"per_session_direction"})
ALLOWED_POINTER_MODES = frozenset({"wire_field_bound_m1"})
ALLOWED_NUMERIC_PROFILES = frozenset({"fixed_point_i64_q16", "lab_float64"})
ALLOWED_STIMULUS_MODES = frozenset({"constant_stimulus_v1"})
ALLOWED_DELIVERY_MODES = frozenset({"stop_and_wait"})
ALLOWED_EPOCH_POLICIES = frozenset({"coordinated_explicit", "disabled"})
ALLOWED_RECOVERY_POLICIES = frozenset({"authenticated_checkpoint_or_rekey"})


class ProfileValidationError(ValueError):
    """Raised when an IDRE v3 profile, bundle, or context violates contract invariants."""


def _lp_bytes(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _lp_str(value: str) -> bytes:
    return _lp_bytes(value.encode("utf-8"))


def compute_vocab_digest_v3(vocab: Vocab, *, policy: str = "strict_vocab_v3") -> bytes:
    """Compute a 32-byte SHA-256 digest binding exact token order, content, and policy.

    This recomputes from `vocab.tokens` rather than trusting any stored `vocab_id`.
    """
    if not isinstance(vocab, Vocab):
        raise ProfileValidationError("vocab must be a Vocab instance")
    if not vocab.tokens:
        raise ProfileValidationError("vocab.tokens must not be empty")
    h = hashlib.sha256()
    h.update(b"IDRE-VOCAB-V3\x00")
    h.update(_lp_str(policy))
    h.update(struct.pack(">I", len(vocab.tokens)))
    for tok in vocab.tokens:
        if not isinstance(tok, str):
            raise ProfileValidationError("vocab tokens must be strings")
        h.update(_lp_str(tok))
    return h.digest()


def max_usable_payload_bytes(
    *,
    max_wire_cell_bytes: int = MAX_WIRE_CELL_BYTES,
    encrypted_headers: bool = False,
) -> int:
    """Compute exact usable payload capacity from the frozen v3 wire layout."""
    overhead = WIRE_HEADER_BYTES + AEAD_TAG_BYTES + CODEC_FRAMING_OVERHEAD_BYTES
    if encrypted_headers:
        overhead += ENCRYPTED_HEADER_OVERHEAD_BYTES
    usable = int(max_wire_cell_bytes) - overhead
    if usable <= 0:
        raise ProfileValidationError("max_wire_cell_bytes leaves no usable payload capacity")
    return usable


@dataclass(frozen=True)
class ProfileV3:
    """Frozen, versioned IDRE v3 protocol profile."""

    bundle_id: bytes
    expected_vocab_digest: bytes
    protocol_version: str = PROTOCOL_VERSION_V3
    suite: str = "HKDF-SHA256+CHACHA20-POLY1305"
    state_scope: str = "per_session_direction"
    pointer_mode: str = "wire_field_bound_m1"
    content_codec: str = "vocab"
    vocab_allow_literals: bool = False
    vocab_policy: str = "strict_vocab_v3"
    field_backend: str = "lattice"
    plasticity: bool = True
    freeze_field: bool = False
    numeric_profile: str = "fixed_point_i64_q16"
    stimulus_mode: str = "constant_stimulus_v1"
    embedding_dim: int = 64
    planes: int = 4
    n_angles: int = 72
    scan_resolution: int = 50
    threshold_q16: int = 32768  # 0.5
    tau_frac_q16: int = 36045  # ~0.55
    anchor_weight_q16: int = 5242880  # 80.0
    learning_rate_q16: int = 32768  # 0.5
    immutable_anchor_ids: Tuple[int, ...] = ()
    max_wire_cell_bytes: int = MAX_WIRE_CELL_BYTES
    max_plaintext_bytes: int = 4023
    encrypted_headers: bool = False
    adaptive_codec_enabled: bool = False
    delivery_mode: str = "stop_and_wait"
    max_in_flight: int = 1
    epoch_policy: str = "coordinated_explicit"
    recovery_policy: str = "authenticated_checkpoint_or_rekey"
    allow_v2_fallback: bool = False
    allow_seed_only_offline_open: bool = False
    healing_mode: str = "none"


@dataclass(frozen=True)
class ProvisioningBundleV3:
    """Private pre-deployment provisioning bundle for an IDRE v3 node."""

    profile: ProfileV3
    network_secret: bytes
    field_init_secret: bytes
    expected_vocab_digest: bytes
    local_node_id: str
    bundle_epoch: int = 1

    def validate(self, vocab: Vocab | None = None) -> None:
        if not isinstance(self.network_secret, (bytes, bytearray)) or len(self.network_secret) < MIN_SECRET_BYTES:
            raise ProfileValidationError(f"network_secret must be at least {MIN_SECRET_BYTES} bytes")
        if not isinstance(self.field_init_secret, (bytes, bytearray)) or len(self.field_init_secret) < MIN_SECRET_BYTES:
            raise ProfileValidationError(f"field_init_secret must be at least {MIN_SECRET_BYTES} bytes")
        if not isinstance(self.expected_vocab_digest, (bytes, bytearray)) or len(self.expected_vocab_digest) != VOCAB_DIGEST_BYTES:
            raise ProfileValidationError(f"expected_vocab_digest must be {VOCAB_DIGEST_BYTES} bytes")
        if not hmac.compare_digest(bytes(self.expected_vocab_digest), bytes(self.profile.expected_vocab_digest)):
            raise ProfileValidationError("bundle expected_vocab_digest disagrees with profile")
        if not isinstance(self.local_node_id, str) or not self.local_node_id.strip():
            raise ProfileValidationError("local_node_id must be a non-empty string")
        if not isinstance(self.bundle_epoch, int) or isinstance(self.bundle_epoch, bool) or not (1 <= self.bundle_epoch <= MAX_UINT32):
            raise ProfileValidationError("bundle_epoch must be a uint32 >= 1")
        _validate_profile_invariants(self.profile)
        if vocab is not None:
            validate_profile(self.profile, vocab)


@dataclass(frozen=True)
class TranscriptV3:
    """Authenticated handshake transcript bound into v3 session derivation."""

    profile_bytes: bytes
    session_id: bytes
    initiator_id: str
    responder_id: str
    initiator_nonce: bytes
    responder_nonce: bytes

    def canonical_bytes(self) -> bytes:
        if not self.profile_bytes:
            raise ProfileValidationError("profile_bytes must not be empty")
        if len(self.session_id) != SESSION_ID_BYTES:
            raise ProfileValidationError(f"session_id must be {SESSION_ID_BYTES} bytes")
        if not self.initiator_id or not self.responder_id:
            raise ProfileValidationError("initiator_id and responder_id must be non-empty")
        if self.initiator_id == self.responder_id:
            raise ProfileValidationError("initiator_id and responder_id must be distinct")
        if len(self.initiator_nonce) != HANDSHAKE_NONCE_BYTES:
            raise ProfileValidationError(f"initiator_nonce must be {HANDSHAKE_NONCE_BYTES} bytes")
        if len(self.responder_nonce) != HANDSHAKE_NONCE_BYTES:
            raise ProfileValidationError(f"responder_nonce must be {HANDSHAKE_NONCE_BYTES} bytes")
        return b"".join(
            [
                b"IDRE-V3-TRANSCRIPT\x00",
                _lp_bytes(self.profile_bytes),
                _lp_bytes(self.session_id),
                _lp_str(self.initiator_id),
                _lp_str(self.responder_id),
                _lp_bytes(self.initiator_nonce),
                _lp_bytes(self.responder_nonce),
            ]
        )


@dataclass(frozen=True)
class MessageContextV3:
    """Immutable per-message domain-separation context."""

    protocol_version: str
    bundle_id: bytes
    session_id: bytes
    role: str
    peer_id: str
    direction: str
    epoch: int
    seq: int
    msg_type: int = MSG_TYPE_DATA

    def canonical_bytes(self) -> bytes:
        if self.protocol_version != PROTOCOL_VERSION_V3:
            raise ProfileValidationError(f"unsupported protocol_version: {self.protocol_version!r}")
        if len(self.bundle_id) != BUNDLE_ID_BYTES:
            raise ProfileValidationError(f"bundle_id must be {BUNDLE_ID_BYTES} bytes")
        if len(self.session_id) != SESSION_ID_BYTES:
            raise ProfileValidationError(f"session_id must be {SESSION_ID_BYTES} bytes")
        if self.role not in VALID_ROLES:
            raise ProfileValidationError(f"invalid role: {self.role!r}")
        if not self.peer_id:
            raise ProfileValidationError("peer_id must be non-empty")
        if self.direction not in DIRECTION_TO_BYTE:
            raise ProfileValidationError(f"invalid direction: {self.direction!r}")
        if not isinstance(self.epoch, int) or isinstance(self.epoch, bool) or not (0 <= self.epoch <= MAX_UINT32):
            raise ProfileValidationError("epoch must be uint32")
        if not isinstance(self.seq, int) or isinstance(self.seq, bool) or not (0 <= self.seq <= MAX_UINT64):
            raise ProfileValidationError("seq must be uint64")
        if self.msg_type not in VALID_MSG_TYPES:
            raise ProfileValidationError(f"invalid msg_type: {self.msg_type!r}")
        return b"".join(
            [
                b"IDRE-V3-MSGCTX\x00",
                _lp_str(self.protocol_version),
                _lp_bytes(self.bundle_id),
                _lp_bytes(self.session_id),
                _lp_str(self.role),
                _lp_str(self.peer_id),
                struct.pack(">B B I Q", DIRECTION_TO_BYTE[self.direction], self.msg_type, self.epoch, self.seq),
            ]
        )


def _validate_profile_invariants(profile: ProfileV3) -> None:
    if not isinstance(profile, ProfileV3):
        raise ProfileValidationError("profile must be a ProfileV3 instance")

    # Anti-downgrade and version checks
    if profile.protocol_version != PROTOCOL_VERSION_V3:
        raise ProfileValidationError(f"unsupported protocol_version: {profile.protocol_version!r}")
    if profile.allow_v2_fallback:
        raise ProfileValidationError("v2 fallback is forbidden in IDRE v3")
    if profile.allow_seed_only_offline_open:
        raise ProfileValidationError("seed-only offline opening is forbidden in IDRE v3")
    if profile.healing_mode != "none":
        raise ProfileValidationError(f"healing_mode must be 'none' in v3, got {profile.healing_mode!r}")

    # Mandatory learned-field & strict-vocab requirements
    if profile.field_backend != "lattice":
        raise ProfileValidationError(f"field_backend must be 'lattice' in v3, got {profile.field_backend!r}")
    if not profile.plasticity:
        raise ProfileValidationError("plasticity must be enabled in IDRE v3")
    if profile.freeze_field:
        raise ProfileValidationError("freeze_field must be False in IDRE v3")
    if profile.content_codec != "vocab":
        raise ProfileValidationError(f"content_codec must be 'vocab' in v3, got {profile.content_codec!r}")
    if profile.vocab_allow_literals:
        raise ProfileValidationError("vocab_allow_literals must be False in IDRE v3")

    # Allowed profile choices
    if profile.suite not in ALLOWED_SUITES:
        raise ProfileValidationError(f"unsupported suite: {profile.suite!r}")
    if profile.state_scope not in ALLOWED_STATE_SCOPES:
        raise ProfileValidationError(f"unsupported state_scope: {profile.state_scope!r}")
    if profile.pointer_mode not in ALLOWED_POINTER_MODES:
        raise ProfileValidationError(f"unsupported pointer_mode: {profile.pointer_mode!r}")
    if profile.numeric_profile not in ALLOWED_NUMERIC_PROFILES:
        raise ProfileValidationError(f"unsupported numeric_profile: {profile.numeric_profile!r}")
    if profile.stimulus_mode not in ALLOWED_STIMULUS_MODES:
        raise ProfileValidationError(f"unsupported stimulus_mode: {profile.stimulus_mode!r}")
    if profile.delivery_mode not in ALLOWED_DELIVERY_MODES:
        raise ProfileValidationError(f"unsupported delivery_mode: {profile.delivery_mode!r}")
    if profile.max_in_flight != 1:
        raise ProfileValidationError("stop_and_wait requires max_in_flight == 1")
    if profile.epoch_policy not in ALLOWED_EPOCH_POLICIES:
        raise ProfileValidationError(f"unsupported epoch_policy: {profile.epoch_policy!r}")
    if profile.recovery_policy not in ALLOWED_RECOVERY_POLICIES:
        raise ProfileValidationError(f"unsupported recovery_policy: {profile.recovery_policy!r}")

    # Identifier & privacy checks
    if not isinstance(profile.bundle_id, bytes) or len(profile.bundle_id) != BUNDLE_ID_BYTES:
        raise ProfileValidationError(f"bundle_id must be {BUNDLE_ID_BYTES} bytes")
    if not isinstance(profile.expected_vocab_digest, bytes) or len(profile.expected_vocab_digest) != VOCAB_DIGEST_BYTES:
        raise ProfileValidationError(f"expected_vocab_digest must be {VOCAB_DIGEST_BYTES} bytes")
    if hmac.compare_digest(profile.bundle_id, profile.expected_vocab_digest[:BUNDLE_ID_BYTES]):
        raise ProfileValidationError("public bundle_id must be opaque and must not reuse expected_vocab_digest")

    # Geometry & numeric bounds
    if profile.embedding_dim <= 0 or profile.planes <= 0 or profile.n_angles <= 0 or profile.scan_resolution <= 0:
        raise ProfileValidationError("field geometry dimensions must be positive")
    if profile.learning_rate_q16 <= 0 or profile.anchor_weight_q16 <= 0:
        raise ProfileValidationError("learning_rate_q16 and anchor_weight_q16 must be positive")
    if len(set(profile.immutable_anchor_ids)) != len(profile.immutable_anchor_ids):
        raise ProfileValidationError("immutable_anchor_ids must not contain duplicates")

    # Wire cell and usable payload bounds
    if profile.max_wire_cell_bytes <= 0 or profile.max_wire_cell_bytes > MAX_WIRE_CELL_BYTES:
        raise ProfileValidationError(f"max_wire_cell_bytes must be in 1..{MAX_WIRE_CELL_BYTES}")
    usable = max_usable_payload_bytes(
        max_wire_cell_bytes=profile.max_wire_cell_bytes,
        encrypted_headers=profile.encrypted_headers,
    )
    if profile.max_plaintext_bytes <= 0 or profile.max_plaintext_bytes > usable:
        raise ProfileValidationError(
            f"max_plaintext_bytes={profile.max_plaintext_bytes} exceeds usable cell capacity ({usable})"
        )


def validate_profile(profile: ProfileV3, vocab: Vocab) -> None:
    """Validate all v3 profile invariants and verify the private vocabulary digest."""
    _validate_profile_invariants(profile)
    actual_digest = compute_vocab_digest_v3(vocab, policy=profile.vocab_policy)
    if not hmac.compare_digest(actual_digest, profile.expected_vocab_digest):
        raise ProfileValidationError("vocabulary digest mismatch against trusted expected_vocab_digest")


def public_profile_metadata(profile: ProfileV3) -> Dict[str, Any]:
    """Return non-secret public profile metadata (explicitly excludes private digests)."""
    _validate_profile_invariants(profile)
    return {
        "protocol_version": profile.protocol_version,
        "bundle_id": profile.bundle_id.hex(),
        "suite": profile.suite,
        "state_scope": profile.state_scope,
        "pointer_mode": profile.pointer_mode,
        "numeric_profile": profile.numeric_profile,
        "delivery_mode": profile.delivery_mode,
        "max_wire_cell_bytes": profile.max_wire_cell_bytes,
    }


def canonical_profile(profile: ProfileV3) -> bytes:
    """Return canonical, deterministic bytes for handshake and KDF transcript binding.

    NOTE: Includes private `expected_vocab_digest` for local transcript hashing;
    never transmit raw `canonical_profile()` bytes to an unauthenticated party.
    """
    _validate_profile_invariants(profile)
    payload = {
        "adaptive_codec_enabled": bool(profile.adaptive_codec_enabled),
        "allow_seed_only_offline_open": bool(profile.allow_seed_only_offline_open),
        "allow_v2_fallback": bool(profile.allow_v2_fallback),
        "anchor_weight_q16": int(profile.anchor_weight_q16),
        "bundle_id": profile.bundle_id.hex(),
        "content_codec": str(profile.content_codec),
        "delivery_mode": str(profile.delivery_mode),
        "embedding_dim": int(profile.embedding_dim),
        "encrypted_headers": bool(profile.encrypted_headers),
        "epoch_policy": str(profile.epoch_policy),
        "expected_vocab_digest": profile.expected_vocab_digest.hex(),
        "field_backend": str(profile.field_backend),
        "freeze_field": bool(profile.freeze_field),
        "healing_mode": str(profile.healing_mode),
        "immutable_anchor_ids": [int(x) for x in sorted(profile.immutable_anchor_ids)],
        "learning_rate_q16": int(profile.learning_rate_q16),
        "max_in_flight": int(profile.max_in_flight),
        "max_plaintext_bytes": int(profile.max_plaintext_bytes),
        "max_wire_cell_bytes": int(profile.max_wire_cell_bytes),
        "n_angles": int(profile.n_angles),
        "numeric_profile": str(profile.numeric_profile),
        "planes": int(profile.planes),
        "plasticity": bool(profile.plasticity),
        "pointer_mode": str(profile.pointer_mode),
        "protocol_version": str(profile.protocol_version),
        "recovery_policy": str(profile.recovery_policy),
        "scan_resolution": int(profile.scan_resolution),
        "state_scope": str(profile.state_scope),
        "stimulus_mode": str(profile.stimulus_mode),
        "suite": str(profile.suite),
        "tau_frac_q16": int(profile.tau_frac_q16),
        "threshold_q16": int(profile.threshold_q16),
        "vocab_allow_literals": bool(profile.vocab_allow_literals),
        "vocab_policy": str(profile.vocab_policy),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return b"IDRE-V3-PROFILE\x00" + encoded
