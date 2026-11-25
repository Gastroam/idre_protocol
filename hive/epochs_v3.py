"""IDRE v3 Coordinated Idempotent Epoch Control and Mode Bypass Guards (Task 10).

- External finalized-block / epoch events are optional coordination inputs,
  NEVER fresh secret entropy.
- Epoch transitions must be ordered (`target_epoch == state.epoch + 1`),
  authenticated under the configured authority key, idempotent on duplicate
  delivery, and applied only after pending old-epoch packets have drained.
- Epoch rotation preserves `state.field` so field-only divergence remains
  rejected before and after every epoch transition.
- Legacy bypasses (seed-only offline opening, multiverse healing, forced
  sessions) are explicitly forbidden in v3.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass, replace
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core.profile_v3 import BUNDLE_ID_BYTES, MAX_UINT32, ProfileV3
from core.session_v3 import DirectionStateV3


class EpochControlError(ValueError):
    """Raised on unauthorized, out-of-order, conflicting, or disallowed epoch/mode operations."""

    def __init__(self, reason: str, message: str = "") -> None:
        self.reason = reason
        super().__init__(message or reason)


@dataclass(frozen=True)
class EpochEventV3:
    bundle_id: bytes
    target_epoch: int
    block_hash: bytes  # 32 bytes
    authority_mac: bytes  # 32 bytes


def _epoch_mac(authority_key: bytes, bundle_id: bytes, target_epoch: int, block_hash: bytes) -> bytes:
    msg = b"IDRE-V3-EPOCH-CTRL|" + bundle_id + struct.pack(">I", target_epoch) + block_hash
    return hmac.new(authority_key, msg, hashlib.sha256).digest()


def create_epoch_event_v3(
    authority_key: bytes,
    *,
    bundle_id: bytes,
    target_epoch: int,
    block_hash: bytes,
) -> EpochEventV3:
    if len(authority_key) < 32:
        raise EpochControlError("bad_authority_key")
    if len(bundle_id) != BUNDLE_ID_BYTES:
        raise EpochControlError("bad_bundle_id")
    if not (1 <= target_epoch <= MAX_UINT32):
        raise EpochControlError("bad_target_epoch")
    if len(block_hash) != 32:
        raise EpochControlError("bad_block_hash")
    mac = _epoch_mac(authority_key, bundle_id, target_epoch, block_hash)
    return EpochEventV3(
        bundle_id=bundle_id,
        target_epoch=target_epoch,
        block_hash=block_hash,
        authority_mac=mac,
    )


def apply_epoch_event_v3(
    state: DirectionStateV3,
    event: EpochEventV3,
    *,
    authority_key: bytes,
    profile: ProfileV3,
) -> Tuple[DirectionStateV3, bool]:
    """Pure, ordered, authenticated, idempotent epoch transition.

    Returns `(next_state, applied)`. Duplicate of the current epoch's exact event
    returns `(state, False)` without advancing twice.
    """
    if profile.epoch_policy == "disabled":
        raise EpochControlError("epoch_policy_disabled")
    if state.closed:
        raise EpochControlError("closed_direction")
    if event.bundle_id != profile.bundle_id:
        raise EpochControlError("bundle_mismatch")

    expected_mac = _epoch_mac(authority_key, event.bundle_id, event.target_epoch, event.block_hash)
    if not hmac.compare_digest(expected_mac, event.authority_mac):
        raise EpochControlError("invalid_epoch_authority_mac")

    # Idempotency check for repeated delivery of the already-committed epoch event
    if event.target_epoch == state.epoch and state.last_epoch_hash:
        if hmac.compare_digest(event.block_hash, state.last_epoch_hash):
            return state, False
        raise EpochControlError("conflicting_epoch_event")

    # Strict ordering: must advance exactly by +1
    if event.target_epoch != state.epoch + 1:
        raise EpochControlError("out_of_order_epoch")

    # Pending old-epoch packets must be drained before rotating
    if state.pending_send is not None:
        raise EpochControlError("pending_send_must_drain_before_epoch")

    next_chain = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=event.block_hash,
        info=b"IDRE-V3-EPOCH-ROTATE|"
        + state.direction.encode("ascii")
        + struct.pack(">I", event.target_epoch),
    ).derive(state.chain_secret)

    next_state = replace(
        state,
        epoch=event.target_epoch,
        next_seq=0,
        chain_secret=next_chain,
        last_epoch_hash=event.block_hash,
        last_accepted=None,
    )
    return next_state, True


def open_offline_envelope_v3(*_args, **_kwargs) -> None:
    """Explicitly disabled in v3: seed-only offline opening cannot bypass current field state."""
    raise EpochControlError(
        "seed_only_offline_open_disabled_in_v3",
        "Seed-only offline opening is forbidden in IDRE v3; restore an authorized checkpoint or rekey.",
    )


def fork_multiverse_timeline_v3(*_args, **_kwargs) -> None:
    """Explicitly disabled in v3: speculative multiverse healing is forbidden."""
    raise EpochControlError(
        "multiverse_healing_disabled_in_v3",
        "Multiverse speculative healing is forbidden in IDRE v3.",
    )


def force_session_v3(*_args, **_kwargs) -> None:
    """Explicitly disabled in v3: unconfirmed forced sessions are forbidden."""
    raise EpochControlError(
        "forced_session_disabled_in_v3",
        "Forced sessions are forbidden in IDRE v3; use mutually confirmed establish_confirmed_session.",
    )
