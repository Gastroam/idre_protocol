"""IDRE v3 Pure Canonical Field State (Task 2).

Implements the portable `fixed_point_i64_q16` neural field transition model:
- 100% deterministic integer arithmetic (Q16.16 fixed-point with signed int64 saturation).
- Zero floating-point operations in the portable profile -> byte-for-byte identical
  across CPU architectures and runtimes.
- Pure state inspection (`field_view`, `encode_field`) and pure transitions (`advance_field`):
  never mutates live state or reinitializes anchors on read.
- Anchors are initialized once from `(profile_digest, anchor_id)` in sorted order,
  completely independent of allocation order, and kept distinct from mutable learners.

Core dependency rule: Python standard library only.
"""

from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import dataclass
from typing import Tuple

from core.profile_v3 import (
    MIN_SECRET_BYTES,
    ProfileV3,
    ProfileValidationError,
    canonical_profile,
)

# --- Frozen Q16.16 Fixed-Point Constants ---

Q16_SHIFT = 16
Q16_ONE = 1 << Q16_SHIFT  # 65536
INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1
UINT64_MAX = (1 << 64) - 1

NUMERIC_PROFILE_ID_FIXED_Q16 = 1

# Learning physics constants in Q16.16 (matching v2 neuron defaults)
INIT_BIAS_Q16 = -2 * Q16_ONE  # -2.0
INIT_WEIGHT_BOUND_Q16 = 3277  # ~0.05 in Q16.16
STIMULUS_CONST_Q16 = 3277  # ~0.05 in Q16.16
Y_TRUE_Q16 = Q16_ONE  # 1.0
MOMENTUM_Q16 = 58982  # round(0.9 * 65536)
DECAY_RATE_Q16 = 9830  # round(0.15 * 65536)

FIELD_ENCODING_MAGIC = b"IDRF3\x00"


class FieldStateError(ValueError):
    """Raised on malformed, out-of-range, or incompatible canonical field state."""


def clamp_i64(value: int) -> int:
    if value < INT64_MIN:
        return INT64_MIN
    if value > INT64_MAX:
        return INT64_MAX
    return int(value)


def div_round_half_away_from_zero(num: int, den: int) -> int:
    """Exact integer division rounded half away from zero for positive denominator."""
    if den <= 0:
        raise FieldStateError("denominator must be positive")
    if num >= 0:
        return (num + (den // 2)) // den
    return -((-num + (den // 2)) // den)


def q16_mul(a: int, b: int) -> int:
    """Multiply two Q16.16 signed integers with half-away-from-zero rounding and int64 saturation."""
    return clamp_i64(div_round_half_away_from_zero(int(a) * int(b), Q16_ONE))


def q16_div(a: int, b: int) -> int:
    """Divide two Q16.16 signed integers with half-away-from-zero rounding and int64 saturation."""
    if b == 0:
        raise FieldStateError("division by zero in q16_div")
    if b < 0:
        a, b = -a, -b
    return clamp_i64(div_round_half_away_from_zero(int(a) * Q16_ONE, int(b)))


def q16_sigmoid(x_q16: int) -> int:
    """Portable, strictly monotone rational sigmoid approximation in Q16.16.

    y = 0.5 * (1 + x / (1 + |x|)), bounded in [0, Q16_ONE],
    exact at x=0 (y=32768), and symmetric: q16_sigmoid(-x) == Q16_ONE - q16_sigmoid(x).
    """
    abs_x = abs(int(x_q16))
    den = Q16_ONE + abs_x
    frac = div_round_half_away_from_zero(int(x_q16) * Q16_ONE, den)
    half_delta = div_round_half_away_from_zero(frac, 2)
    y = (Q16_ONE // 2) + half_delta
    if y < 0:
        return 0
    if y > Q16_ONE:
        return Q16_ONE
    return int(y)


def _sha256_expand(domain: bytes, seed_material: bytes, n_bytes: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n_bytes:
        h = hashlib.sha256()
        h.update(domain)
        h.update(seed_material)
        h.update(struct.pack(">I", counter))
        out.extend(h.digest())
        counter += 1
    return bytes(out[:n_bytes])


def _derive_unit_anchor_q16(profile_digest: bytes, anchor_id: int, dim: int, anchor_weight_q16: int) -> Tuple[int, ...]:
    """Deterministically derive an immutable anchor vector scaled to anchor_weight_q16."""
    raw = _sha256_expand(
        b"IDRE-V3-ANCHOR-INIT\x00",
        profile_digest + struct.pack(">qI", int(anchor_id), int(dim)),
        dim * 4,
    )
    # Map each uint32 to signed Q16 in [-Q16_ONE, +Q16_ONE]
    vec = []
    for i in range(dim):
        u = struct.unpack(">I", raw[i * 4 : (i + 1) * 4])[0]
        # Signed centered value in [-32768, 32767]
        centered = (u & 0xFFFF) - 32768
        vec.append(centered * 2)
    sq_sum = sum(v * v for v in vec)
    norm_q16 = math.isqrt(sq_sum)
    if norm_q16 == 0:
        # Fallback deterministic non-zero unit vector along axis 0
        out = [0] * dim
        out[0] = clamp_i64(anchor_weight_q16)
        return tuple(out)
    return tuple(
        clamp_i64(div_round_half_away_from_zero(v * anchor_weight_q16, norm_q16))
        for v in vec
    )


@dataclass(frozen=True)
class AcceptedEventV3:
    """Authenticated protocol event that advances canonical directional field state."""

    event_type: str  # e.g. "data_accepted"
    seq: int
    epoch: int
    token_digest: bytes = b""

    def __post_init__(self) -> None:
        if not self.event_type:
            raise FieldStateError("event_type must be non-empty")
        if not isinstance(self.seq, int) or isinstance(self.seq, bool) or not (0 <= self.seq <= UINT64_MAX):
            raise FieldStateError("seq must be uint64")
        if not isinstance(self.epoch, int) or isinstance(self.epoch, bool) or not (0 <= self.epoch <= 0xFFFFFFFF):
            raise FieldStateError("epoch must be uint32")


@dataclass(frozen=True)
class FieldStateV3:
    """Complete, immutable, canonical neural field transition state.

    Excludes local telemetry (timestamps, caches, object IDs).
    """

    profile_digest: bytes  # 32 bytes: SHA-256(canonical_profile(profile))
    numeric_profile_id: int
    dim: int
    learning_rate_q16: int
    weight_cap_q16: int
    age: int
    bias_q16: int
    weights_q16: Tuple[int, ...]
    velocity_q16: Tuple[int, ...]
    anchors: Tuple[Tuple[int, Tuple[int, ...]], ...]  # sorted by anchor_id

    def __post_init__(self) -> None:
        if len(self.profile_digest) != 32:
            raise FieldStateError("profile_digest must be 32 bytes")
        if self.numeric_profile_id != NUMERIC_PROFILE_ID_FIXED_Q16:
            raise FieldStateError(f"unsupported numeric_profile_id: {self.numeric_profile_id}")
        if self.dim <= 0:
            raise FieldStateError("dim must be positive")
        if self.learning_rate_q16 <= 0 or self.weight_cap_q16 <= 0:
            raise FieldStateError("learning_rate_q16 and weight_cap_q16 must be positive")
        if not (0 <= self.age <= UINT64_MAX):
            raise FieldStateError("age must be uint64")
        if not (INT64_MIN <= self.bias_q16 <= INT64_MAX):
            raise FieldStateError("bias_q16 out of int64 range")
        if len(self.weights_q16) != self.dim or len(self.velocity_q16) != self.dim:
            raise FieldStateError("weights_q16 and velocity_q16 must match dim")
        for w, v in zip(self.weights_q16, self.velocity_q16):
            if not (INT64_MIN <= w <= INT64_MAX) or not (INT64_MIN <= v <= INT64_MAX):
                raise FieldStateError("weight or velocity out of int64 range")
        prev_aid = None
        for aid, avec in self.anchors:
            if prev_aid is not None and aid <= prev_aid:
                raise FieldStateError("anchors must be strictly sorted by anchor_id")
            if len(avec) != self.dim:
                raise FieldStateError("anchor vector length mismatch")
            prev_aid = aid


@dataclass(frozen=True)
class FieldViewV3:
    """Immutable private derived view of canonical field state.

    Has no public wire serialization; __repr__ redacts binding bytes.
    """

    profile_digest: bytes
    age: int
    binding_bytes: bytes  # 32-byte private binding over full canonical state

    def __repr__(self) -> str:
        return f"FieldViewV3(age={self.age}, binding_bytes=<redacted 32B>)"


def initialize_field(profile: ProfileV3, field_seed: bytes, context: bytes) -> FieldStateV3:
    """Pure deterministic initialization of canonical FieldStateV3.

    Independent of global RNG state and neuron allocation order.
    """
    if profile.numeric_profile != "fixed_point_i64_q16":
        raise ProfileValidationError(
            f"portable initialize_field requires numeric_profile='fixed_point_i64_q16', got {profile.numeric_profile!r}"
        )
    if not isinstance(field_seed, (bytes, bytearray)) or len(field_seed) < MIN_SECRET_BYTES:
        raise FieldStateError(f"field_seed must be at least {MIN_SECRET_BYTES} bytes")
    if not isinstance(context, (bytes, bytearray)):
        raise FieldStateError("context must be bytes")

    profile_bytes = canonical_profile(profile)
    profile_digest = hashlib.sha256(profile_bytes).digest()
    dim = int(profile.embedding_dim)

    raw = _sha256_expand(
        b"IDRE-V3-FIELD-INIT\x00",
        profile_digest
        + struct.pack(">I", len(field_seed))
        + bytes(field_seed)
        + struct.pack(">I", len(context))
        + bytes(context),
        dim * 2,
    )
    span = 2 * INIT_WEIGHT_BOUND_Q16 + 1
    weights = []
    for i in range(dim):
        u16 = struct.unpack(">H", raw[i * 2 : (i + 1) * 2])[0]
        w = (u16 % span) - INIT_WEIGHT_BOUND_Q16
        weights.append(int(w))

    anchors = tuple(
        (
            int(aid),
            _derive_unit_anchor_q16(profile_digest, int(aid), dim, int(profile.anchor_weight_q16)),
        )
        for aid in sorted(profile.immutable_anchor_ids)
    )

    return FieldStateV3(
        profile_digest=profile_digest,
        numeric_profile_id=NUMERIC_PROFILE_ID_FIXED_Q16,
        dim=dim,
        learning_rate_q16=int(profile.learning_rate_q16),
        weight_cap_q16=int(profile.anchor_weight_q16),
        age=0,
        bias_q16=INIT_BIAS_Q16,
        weights_q16=tuple(weights),
        velocity_q16=(0,) * dim,
        anchors=anchors,
    )


def encode_field(state: FieldStateV3) -> bytes:
    """Canonical, typed, length-delimited binary encoding of FieldStateV3."""
    if not isinstance(state, FieldStateV3):
        raise FieldStateError("state must be a FieldStateV3 instance")
    out = bytearray()
    out.extend(FIELD_ENCODING_MAGIC)
    out.extend(struct.pack(">B", state.numeric_profile_id))
    out.extend(state.profile_digest)
    out.extend(
        struct.pack(
            ">I q q Q q",
            state.dim,
            state.learning_rate_q16,
            state.weight_cap_q16,
            state.age,
            state.bias_q16,
        )
    )
    out.extend(struct.pack(f">{state.dim}q", *state.weights_q16))
    out.extend(struct.pack(f">{state.dim}q", *state.velocity_q16))
    out.extend(struct.pack(">I", len(state.anchors)))
    for aid, avec in state.anchors:
        out.extend(struct.pack(">q", aid))
        out.extend(struct.pack(f">{state.dim}q", *avec))
    return bytes(out)


def decode_field(raw: bytes) -> FieldStateV3:
    """Strictly decode canonical FieldStateV3 bytes, rejecting any malformed or trailing data."""
    if not isinstance(raw, (bytes, bytearray)):
        raise FieldStateError("raw must be bytes")
    bb = bytes(raw)
    hdr_len = len(FIELD_ENCODING_MAGIC) + 1 + 32 + 4 + 8 + 8 + 8 + 8
    if len(bb) < hdr_len + 4:
        raise FieldStateError("truncated field state header")
    if bb[: len(FIELD_ENCODING_MAGIC)] != FIELD_ENCODING_MAGIC:
        raise FieldStateError("bad field state magic")
    off = len(FIELD_ENCODING_MAGIC)
    (num_id,) = struct.unpack(">B", bb[off : off + 1])
    off += 1
    profile_digest = bb[off : off + 32]
    off += 32
    dim, lr_q16, cap_q16, age, bias_q16 = struct.unpack(">I q q Q q", bb[off : off + 36])
    off += 36
    if dim <= 0 or dim > 65536:
        raise FieldStateError(f"invalid dim: {dim}")

    vec_bytes = dim * 8
    if off + (2 * vec_bytes) + 4 > len(bb):
        raise FieldStateError("truncated field state vectors")
    weights = struct.unpack(f">{dim}q", bb[off : off + vec_bytes])
    off += vec_bytes
    velocity = struct.unpack(f">{dim}q", bb[off : off + vec_bytes])
    off += vec_bytes
    (n_anchors,) = struct.unpack(">I", bb[off : off + 4])
    off += 4

    expected_remaining = n_anchors * (8 + vec_bytes)
    if len(bb) - off != expected_remaining:
        raise FieldStateError("length mismatch or trailing bytes in field state")

    anchors = []
    for _ in range(n_anchors):
        (aid,) = struct.unpack(">q", bb[off : off + 8])
        off += 8
        avec = struct.unpack(f">{dim}q", bb[off : off + vec_bytes])
        off += vec_bytes
        anchors.append((int(aid), tuple(int(x) for x in avec)))

    return FieldStateV3(
        profile_digest=profile_digest,
        numeric_profile_id=num_id,
        dim=dim,
        learning_rate_q16=lr_q16,
        weight_cap_q16=cap_q16,
        age=age,
        bias_q16=bias_q16,
        weights_q16=tuple(int(x) for x in weights),
        velocity_q16=tuple(int(x) for x in velocity),
        anchors=tuple(anchors),
    )


def advance_field(state: FieldStateV3, event: AcceptedEventV3) -> FieldStateV3:
    """Pure fixed-point Q16.16 neuron transition for `constant_stimulus_v1`.

    Does not mutate `state`; returns a new `FieldStateV3`. Anchors remain untouched.
    """
    if not isinstance(state, FieldStateV3):
        raise FieldStateError("state must be a FieldStateV3 instance")
    if not isinstance(event, AcceptedEventV3):
        raise FieldStateError("event must be an AcceptedEventV3 instance")
    if state.age >= UINT64_MAX:
        raise FieldStateError("field age overflow")

    next_age = state.age + 1

    # 1. logits = dot(x, weights) + bias  (constant stimulus x_i = STIMULUS_CONST_Q16)
    dot_acc = 0
    for w in state.weights_q16:
        dot_acc += STIMULUS_CONST_Q16 * w
    logits_q16 = clamp_i64(div_round_half_away_from_zero(dot_acc, Q16_ONE) + state.bias_q16)

    # 2. y_pred = q16_sigmoid(logits), err = y_pred - 1.0
    y_pred_q16 = q16_sigmoid(logits_q16)
    err_q16 = y_pred_q16 - Y_TRUE_Q16

    # 3. lr = initial_lr / (1 + decay_rate * age)
    denom_q16 = Q16_ONE + DECAY_RATE_Q16 * next_age
    lr_q16 = q16_div(state.learning_rate_q16, denom_q16)

    # 4. grad_i = x_i * err; velocity = velocity * momentum - grad * lr; weights += velocity
    grad_q16 = q16_mul(STIMULUS_CONST_Q16, err_q16)
    step_q16 = q16_mul(grad_q16, lr_q16)

    new_vel = []
    new_w = []
    for w, v in zip(state.weights_q16, state.velocity_q16):
        v_next = clamp_i64(q16_mul(v, MOMENTUM_Q16) - step_q16)
        w_next = clamp_i64(w + v_next)
        new_vel.append(v_next)
        new_w.append(w_next)

    # 5. bias = bias - lr * err
    new_bias = clamp_i64(state.bias_q16 - q16_mul(lr_q16, err_q16))

    # 6. L2 norm cap using exact integer sqrt
    sq_sum = sum(w * w for w in new_w)
    norm_q16 = math.isqrt(sq_sum)
    if norm_q16 > state.weight_cap_q16:
        new_w = [
            clamp_i64(div_round_half_away_from_zero(w * state.weight_cap_q16, norm_q16))
            for w in new_w
        ]
        new_vel = [
            clamp_i64(div_round_half_away_from_zero(v, 2))
            for v in new_vel
        ]

    return FieldStateV3(
        profile_digest=state.profile_digest,
        numeric_profile_id=state.numeric_profile_id,
        dim=state.dim,
        learning_rate_q16=state.learning_rate_q16,
        weight_cap_q16=state.weight_cap_q16,
        age=next_age,
        bias_q16=new_bias,
        weights_q16=tuple(new_w),
        velocity_q16=tuple(new_vel),
        anchors=state.anchors,
    )


def field_view(state: FieldStateV3, profile: ProfileV3) -> FieldViewV3:
    """Pure extraction of a private FieldViewV3 binding the full canonical state."""
    expected_profile_digest = hashlib.sha256(canonical_profile(profile)).digest()
    if state.profile_digest != expected_profile_digest:
        raise FieldStateError("field state profile_digest does not match provided profile")
    encoded = encode_field(state)
    binding = hashlib.sha256(b"IDRE-V3-FIELD-VIEW\x00" + encoded).digest()
    return FieldViewV3(
        profile_digest=state.profile_digest,
        age=state.age,
        binding_bytes=binding,
    )
