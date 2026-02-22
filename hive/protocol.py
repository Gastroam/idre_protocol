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


def derive_route_tag(bits: List[int], epoch: int, domain: bytes = b"ROUTE/") -> bytes:
    """Derive a 16-byte rotating route tag from field fingerprint bits and epoch.
    
    Changes every epoch so an observer cannot link traffic across epochs.
    16 bytes = 128-bit birthday collision threshold (~2^64 operations).
    """
    bits_bytes = bytes(int(b) & 1 for b in bits)
    full = hashlib.sha256(
        bytes(domain) + bits_bytes + int(epoch).to_bytes(8, "big")
    ).digest()
    return full[:16]


def _header_key(bits: List[int], session_id: str, nonce: int) -> bytes:
    """Derive key for header encryption."""
    bits_bytes = bytes(int(b) & 1 for b in bits)
    ctx = f"{session_id}:{int(nonce)}".encode("utf-8")
    return hashlib.sha256(b"HDR/" + bits_bytes + b":" + ctx).digest()


def _expand_bytes(seed: bytes, n: int, domain: bytes) -> bytes:
    """Expand seed into n bytes using SHA256-CTR (same as physics_v12)."""
    out = bytearray()
    counter = 0
    while len(out) < int(n):
        out.extend(hashlib.sha256(domain + seed + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(out[:int(n)])


def encrypt_header(
    header_dict: Dict[str, Any],
    bits: List[int],
    session_id: str,
    nonce: int,
) -> bytes:
    """Encrypt a header dict into opaque bytes.
    
    Uses XOR with a keystream derived from the field bits — same
    crypto pattern as the payload cipher, but keyed differently
    (domain separation via "HDR/" prefix).
    """
    plaintext = canonical_json(header_dict)
    key = _header_key(bits, session_id, nonce)
    keystream = _expand_bytes(key, len(plaintext), b"HDRSTREAM/")
    ct = bytes(a ^ b for a, b in zip(plaintext, keystream))
    # Prepend length so we know how much to decrypt
    return struct.pack(">H", len(ct)) + ct


def decrypt_header(
    encrypted: bytes,
    bits: List[int],
    session_id: str,
    nonce: int,
) -> Tuple[bool, Dict[str, Any]]:
    """Decrypt an encrypted header back to a dict.
    
    Returns:
        (success, header_dict). On failure, returns (False, {}).
    """
    if len(encrypted) < 2:
        return False, {}
    ct_len = struct.unpack(">H", encrypted[:2])[0]
    if len(encrypted) < 2 + ct_len:
        return False, {}
    ct = encrypted[2:2 + ct_len]

    key = _header_key(bits, session_id, nonce)
    keystream = _expand_bytes(key, ct_len, b"HDRSTREAM/")
    plaintext = bytes(a ^ b for a, b in zip(ct, keystream))

    try:
        import json
        hdr = json.loads(plaintext.decode("utf-8"))
        if not isinstance(hdr, dict):
            return False, {}
        return True, hdr
    except Exception:
        return False, {}


__all__ = [
    "aad_with_epoch_anchor",
    "codec_session_key",
    "decrypt_header",
    "derive_route_tag",
    "encrypt_header",
    "forced_chain_hash",
    "genesis_chain_hash",
    "payload_ints_to_bytes",
    "update_chain_hash",
    "verify_req_aad",
    "verify_req_header",
]
