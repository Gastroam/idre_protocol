from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Any, Dict, Iterable, List, Tuple

from .utils import canonical_json


def payload_ints_to_bytes(payload: List[int] | Iterable[int]) -> bytes:
    return bytes(int(x) & 0xFF for x in payload)


def aad_with_epoch_anchor(aad: bytes, *, chain_hash: bytes, seq: int) -> bytes:
    return (aad or b"") + bytes(chain_hash) + struct.pack(">Q", int(seq))


def update_chain_hash(chain_hash: bytes, seq: int) -> bytes:
    # Epoch Anchor: bind to Sequence Number (allows Healing/BF logic)
    return hashlib.sha256(bytes(chain_hash) + struct.pack(">Q", int(seq))).digest()


def genesis_chain_hash(seed: int, session_id: str) -> bytes:
    # Genesis Hash = HMAC(seed, "GENESIS:" + sess_id)
    return hmac.new(str(seed).encode(), f"GENESIS:{session_id}".encode(), hashlib.sha256).digest()


def codec_session_key(seed: int, session_id: str) -> bytes:
    return hmac.new(str(seed).encode(), f"CODEC:{session_id}".encode(), hashlib.sha256).digest()


def forced_chain_hash(seed: int, session_id: str) -> bytes:
    # Legacy/forced mode uses SHA256 instead of HMAC for genesis.
    genesis_input = f"{seed}:{session_id}:GENESIS".encode("utf-8")
    return hashlib.sha256(genesis_input).digest()


def verify_req_header(
    *,
    field_profile_id: str,
    challenge: str,
    session_id: str,
    nonce: int,
    ephemeral_salt: int,
) -> Dict[str, Any]:
    return {
        "type": "VERIFY_REQ",
        "field_profile_id": str(field_profile_id),
        "challenge": str(challenge),
        "session_id": str(session_id),
        "nonce": int(nonce),
        "ephemeral_salt": int(ephemeral_salt),
    }


def verify_req_aad(
    *,
    field_profile_id: str,
    challenge: str,
    session_id: str,
    nonce: int,
    ephemeral_salt: int,
) -> Tuple[Dict[str, Any], bytes]:
    hdr = verify_req_header(
        field_profile_id=str(field_profile_id),
        challenge=str(challenge),
        session_id=str(session_id),
        nonce=int(nonce),
        ephemeral_salt=int(ephemeral_salt),
    )
    return hdr, canonical_json(hdr)


__all__ = [
    "aad_with_epoch_anchor",
    "codec_session_key",
    "forced_chain_hash",
    "genesis_chain_hash",
    "payload_ints_to_bytes",
    "update_chain_hash",
    "verify_req_aad",
    "verify_req_header",
]
