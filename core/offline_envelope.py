from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import struct
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .physics_v12 import (
    compute_block_salt,
    derive_keystream_and_permutation,
    inverse_permute,
    permute,
    xor_bytes,
)
from .wire import canonical_json

MAC_LEN = 32
MAX_CT_LEN = 4_000_000  # defensive cap for offline blobs

MAGIC8 = b"IDREOFF1"  # 8 bytes
BLOCK_SIZE = 32


def _now_ms() -> int:
    return int(time.time() * 1000.0)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _mac_key(bits: List[int], *, session_id: str, nonce: int, ephemeral_salt: int) -> bytes:
    bits_bytes = bytes(int(b) & 1 for b in bits)
    ctx = f"{session_id}:{int(ephemeral_salt)}:{int(nonce)}".encode("utf-8")
    return _sha256(b"MACKEY/" + bits_bytes + b":" + ctx)


def _crypt(bits: List[int], *, framed: List[int], session_id: str, nonce: int, ephemeral_salt: int, encrypt: bool) -> List[int]:
    combined = f"{session_id}:{int(ephemeral_salt)}:{int(nonce)}"
    if encrypt:
        pt = list(framed)
        while len(pt) % BLOCK_SIZE != 0:
            pt.append(0)
        out: List[int] = []
        for idx in range(len(pt) // BLOCK_SIZE):
            chunk = pt[idx * BLOCK_SIZE : (idx + 1) * BLOCK_SIZE]
            salt = compute_block_salt(bits, combined, idx)
            k_t, pi_t = derive_keystream_and_permutation(salt, BLOCK_SIZE)
            out.extend(xor_bytes(permute(chunk, pi_t), k_t))
        return out

    ct = list(framed)
    if len(ct) % BLOCK_SIZE != 0:
        ct = ct[: (len(ct) // BLOCK_SIZE) * BLOCK_SIZE]
    out = []
    for idx in range(len(ct) // BLOCK_SIZE):
        chunk = ct[idx * BLOCK_SIZE : (idx + 1) * BLOCK_SIZE]
        salt = compute_block_salt(bits, combined, idx)
        k_t, pi_t = derive_keystream_and_permutation(salt, BLOCK_SIZE)
        out.extend(inverse_permute(xor_bytes(chunk, k_t), pi_t))
    return out


def _encrypt_bytes(
    bits: List[int],
    *,
    plaintext: bytes,
    session_id: str,
    nonce: int,
    ephemeral_salt: int,
    aad: bytes,
    pad_bytes: int = 0,
) -> bytes:
    # Prefix length to avoid ambiguity with zero padding.
    blob = struct.pack(">I", int(len(plaintext))) + bytes(plaintext)
    pt = [b for b in blob]
    ct = _crypt(bits, framed=pt, session_id=session_id, nonce=nonce, ephemeral_salt=ephemeral_salt, encrypt=True)
    ct_b = bytes(int(x) & 0xFF for x in ct)
    key = _mac_key(bits, session_id=session_id, nonce=nonce, ephemeral_salt=ephemeral_salt)
    tag = hmac.new(key, (aad or b"") + ct_b, hashlib.sha256).digest()
    if len(tag) != MAC_LEN:
        raise ValueError("bad_tag_len")

    # Byte framing (offline uses bytes transport, not list-of-int framing):
    #   [u32 ct_len][ct_bytes...][tag(32)][noise/pad...]
    framed_b = bytearray()
    framed_b += struct.pack(">I", int(len(ct_b)))
    framed_b += ct_b
    framed_b += tag

    # Optional noise pad (deterministic from ct) to keep output stable without sharing randomness.
    if pad_bytes and pad_bytes > 0:
        seed = _sha256(ct_b)
        pad = bytearray()
        counter = 0
        while len(pad) < int(pad_bytes):
            pad.extend(_sha256(b"PAD/" + seed + counter.to_bytes(4, "big")))
            counter += 1
        framed_b += pad[: int(pad_bytes)]
    return bytes(framed_b)


def _decrypt_bytes(
    bits: List[int],
    *,
    payload_bytes: bytes,
    session_id: str,
    nonce: int,
    ephemeral_salt: int,
    aad: bytes,
) -> Optional[bytes]:
    if not isinstance(payload_bytes, (bytes, bytearray)):
        return None
    bb = bytes(payload_bytes)
    if len(bb) < 4 + MAC_LEN:
        return None
    n = struct.unpack(">I", bb[:4])[0]
    if int(n) < 0 or int(n) > int(MAX_CT_LEN):
        return None
    off = 4
    if off + int(n) + MAC_LEN > len(bb):
        return None
    ct_b = bb[off : off + int(n)]
    off += int(n)
    tag = bb[off : off + MAC_LEN]
    if len(ct_b) != int(n) or len(tag) != MAC_LEN:
        return None
    key = _mac_key(bits, session_id=session_id, nonce=nonce, ephemeral_salt=ephemeral_salt)
    exp = hmac.new(key, (aad or b"") + ct_b, hashlib.sha256).digest()
    if not hmac.compare_digest(exp, tag):
        return None
    ct = [b for b in ct_b]
    pt = _crypt(bits, framed=ct, session_id=session_id, nonce=nonce, ephemeral_salt=ephemeral_salt, encrypt=False)
    blob = bytes(int(x) & 0xFF for x in pt)
    if len(blob) < 4:
        return None
    n = struct.unpack(">I", blob[:4])[0]
    if n < 0:
        return None
    data = blob[4 : 4 + int(n)]
    if len(data) != int(n):
        return None
    return data


@dataclass
class OfflineHeader:
    """Standard header for an offline-encoded IDRE envelope."""
    type: str
    proto: str
    field_profile_id: str
    session_id: str
    ephemeral_salt: int
    nonce: int
    created_at_ms: int
    expires_at_ms: int
    src_hint: str = ""
    dst_hint: str = ""
    purpose: str = ""
    compressed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "proto": self.proto,
            "field_profile_id": self.field_profile_id,
            "session_id": self.session_id,
            "ephemeral_salt": int(self.ephemeral_salt),
            "nonce": int(self.nonce),
            "created_at_ms": int(self.created_at_ms),
            "expires_at_ms": int(self.expires_at_ms),
            "src_hint": str(self.src_hint),
            "dst_hint": str(self.dst_hint),
            "purpose": str(self.purpose),
            "compressed": bool(self.compressed),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "OfflineHeader":
        return cls(
            type=str(d.get("type", "")),
            proto=str(d.get("proto", "")),
            field_profile_id=str(d.get("field_profile_id", "")),
            session_id=str(d.get("session_id", "")),
            ephemeral_salt=int(d.get("ephemeral_salt", 0)),
            nonce=int(d.get("nonce", 0)),
            created_at_ms=int(d.get("created_at_ms", 0)),
            expires_at_ms=int(d.get("expires_at_ms", 0)),
            src_hint=str(d.get("src_hint", "")),
            dst_hint=str(d.get("dst_hint", "")),
            purpose=str(d.get("purpose", "")),
            compressed=bool(d.get("compressed", False)),
        )


def seal(
    *,
    bits: List[int],
    plaintext: bytes,
    field_profile_id: str,
    expires_in_ms: int,
    created_at_ms: Optional[int] = None,
    session_id: Optional[str] = None,
    ephemeral_salt: Optional[int] = None,
    nonce: Optional[int] = None,
    src_hint: str = "",
    dst_hint: str = "",
    purpose: str = "",
    compressed: bool = False,
    pad_bytes: int = 0,
) -> bytes:
    """
    Encrypt and MAC a plaintext message using the provided fingerprint bits.

    Constructs an OfflineHeader, serializes it, encrypts the payload, and encapsulates
    them into a binary MAGIC envelope.
    """
    c_ms = int(_now_ms() if created_at_ms is None else created_at_ms)
    x_ms = int(c_ms + int(expires_in_ms))
    sid = session_id or secrets.token_hex(16)
    eph = int(ephemeral_salt if ephemeral_salt is not None else secrets.randbits(31))
    nn = int(nonce if nonce is not None else secrets.randbits(64))

    hdr = OfflineHeader(
        type="OFFLINE",
        proto="IDRE-OFFLINE/1",
        field_profile_id=str(field_profile_id),
        session_id=str(sid),
        ephemeral_salt=int(eph),
        nonce=int(nn),
        created_at_ms=int(c_ms),
        expires_at_ms=int(x_ms),
        src_hint=str(src_hint),
        dst_hint=str(dst_hint),
        purpose=str(purpose),
        compressed=bool(compressed),
    )
    hdr_dict = hdr.to_dict()
    aad = canonical_json(hdr_dict)
    payload_bytes = _encrypt_bytes(
        bits,
        plaintext=bytes(plaintext),
        session_id=hdr.session_id,
        nonce=hdr.nonce,
        ephemeral_salt=hdr.ephemeral_salt,
        aad=aad,
        pad_bytes=int(pad_bytes),
    )

    hdr_json = json.dumps(hdr_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(hdr_json) > 65535:
        raise ValueError("header_too_large")
    if len(payload_bytes) > 0xFFFFFFFF:
        raise ValueError("payload_too_large")

    return MAGIC8 + struct.pack(">H", len(hdr_json)) + hdr_json + struct.pack(">I", len(payload_bytes)) + payload_bytes


def open_envelope(
    *,
    bits: List[int],
    blob: bytes,
    expected_field_profile_id: str,
    enforce_time: bool = True,
    now_ms: Optional[int] = None,
    skew_ms: int = 120_000,
) -> Tuple[bool, str, Optional[OfflineHeader], Optional[bytes]]:
    """
    Returns (ok, reason, header, plaintext).
    """
    if not isinstance(blob, (bytes, bytearray)):
        return False, "bad_type", None, None
    bb = bytes(blob)
    if len(bb) < 8 + 2 + 4:
        return False, "too_short", None, None
    if bb[:8] != MAGIC8:
        return False, "bad_magic", None, None
    off = 8
    hdr_len = struct.unpack(">H", bb[off : off + 2])[0]
    off += 2
    if off + hdr_len + 4 > len(bb):
        return False, "bad_header_len", None, None
    hdr_json = bb[off : off + hdr_len]
    off += hdr_len
    try:
        hdr_dict = json.loads(hdr_json.decode("utf-8"))
    except Exception:
        return False, "bad_header_json", None, None
    if not isinstance(hdr_dict, dict):
        return False, "bad_header_json", None, None
    hdr = OfflineHeader.from_dict(hdr_dict)

    if hdr.proto != "IDRE-OFFLINE/1" or hdr.type != "OFFLINE":
        return False, "bad_proto", hdr, None
    if str(hdr.field_profile_id) != str(expected_field_profile_id):
        return False, "wrong_profile", hdr, None

    payload_len = struct.unpack(">I", bb[off : off + 4])[0]
    off += 4
    if off + payload_len > len(bb):
        return False, "bad_payload_len", hdr, None
    payload_bytes = bb[off : off + payload_len]

    if enforce_time:
        n_ms = int(_now_ms() if now_ms is None else now_ms)
        if int(hdr.expires_at_ms) > 0 and n_ms > int(hdr.expires_at_ms):
            return False, "expired", hdr, None
        if int(hdr.created_at_ms) > 0 and int(hdr.created_at_ms) > int(n_ms) + int(skew_ms):
            return False, "clock_skew", hdr, None

    aad = canonical_json(hdr.to_dict())
    pt = _decrypt_bytes(
        bits,
        payload_bytes=payload_bytes,
        session_id=hdr.session_id,
        nonce=hdr.nonce,
        ephemeral_salt=hdr.ephemeral_salt,
        aad=aad,
    )
    if pt is None:
        return False, "corrupt", hdr, None
    return True, "ok", hdr, pt
