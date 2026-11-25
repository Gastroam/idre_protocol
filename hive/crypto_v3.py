"""IDRE v3 ChaCha20-Poly1305 AEAD Wrapper and Exact 54-Byte Binary Framing (Task 6)."""

from __future__ import annotations

import hmac
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from core.profile_v3 import (
    AEAD_TAG_BYTES,
    BUNDLE_ID_BYTES,
    BYTE_TO_DIRECTION,
    DIRECTION_TO_BYTE,
    ENCRYPTED_HEADER_OVERHEAD_BYTES,
    FLAG_ENCRYPTED_HEADER,
    MAX_WIRE_CELL_BYTES,
    SESSION_ID_BYTES,
    VALID_FLAGS_MASK,
    VALID_MSG_TYPES,
    WIRE_HEADER_BYTES,
    WIRE_MAGIC_V3,
    WIRE_VERSION_BYTE_V3,
)

# 4s magic, B ver, B msg_type, B flags, B dir, 16s bundle_id, 16s session_id, I epoch, Q seq, H ct_len
_HEADER_STRUCT = struct.Struct(">4s B B B B 16s 16s I Q H")
assert _HEADER_STRUCT.size == WIRE_HEADER_BYTES

# Encrypted inner header plaintext: 16s bundle_id + 16s session_id + I epoch + Q seq + B dir + B msg_type + H pad(0) = 48 bytes
_INNER_HEADER_STRUCT = struct.Struct(">16s 16s I Q B B H")
assert _INNER_HEADER_STRUCT.size == 48
assert 16 + _INNER_HEADER_STRUCT.size + AEAD_TAG_BYTES == ENCRYPTED_HEADER_OVERHEAD_BYTES


class CryptoV3Error(ValueError):
    """Raised on framing, resource-bound, or AEAD authentication failure."""

    def __init__(self, reason: str, message: str = "") -> None:
        self.reason = reason
        super().__init__(message or reason)


@dataclass(frozen=True)
class WireFrameV3:
    msg_type: int
    flags: int
    direction: str
    bundle_id: bytes
    session_id: bytes
    epoch: int
    seq: int
    header_bytes: bytes  # exact 54-byte outer header (used as AAD)
    body_bytes: bytes  # ciphertext (or route_tag + enc_hdr + ciphertext)


def aead_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    if len(key) != 32:
        raise CryptoV3Error("bad_key_len", "ChaCha20-Poly1305 key must be 32 bytes")
    if len(nonce) != 12:
        raise CryptoV3Error("bad_nonce_len", "ChaCha20-Poly1305 nonce must be 12 bytes")
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def aead_open(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    if len(key) != 32:
        raise CryptoV3Error("bad_key_len", "ChaCha20-Poly1305 key must be 32 bytes")
    if len(nonce) != 12:
        raise CryptoV3Error("bad_nonce_len", "ChaCha20-Poly1305 nonce must be 12 bytes")
    if len(ciphertext) < AEAD_TAG_BYTES:
        raise CryptoV3Error("truncated_ciphertext", "ciphertext shorter than AEAD tag")
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise CryptoV3Error("field_or_mac_mismatch", "AEAD authentication failed") from exc


def pack_frame_v3(
    *,
    msg_type: int,
    flags: int,
    direction: str,
    bundle_id: bytes,
    session_id: bytes,
    epoch: int,
    seq: int,
    body_bytes: bytes,
    max_wire_cell_bytes: int = MAX_WIRE_CELL_BYTES,
) -> bytes:
    if msg_type not in VALID_MSG_TYPES:
        raise CryptoV3Error("bad_msg_type")
    if flags & ~VALID_FLAGS_MASK:
        raise CryptoV3Error("bad_flags")
    if direction not in DIRECTION_TO_BYTE:
        raise CryptoV3Error("bad_direction")
    if len(bundle_id) != BUNDLE_ID_BYTES or len(session_id) != SESSION_ID_BYTES:
        raise CryptoV3Error("bad_identifier_len")
    total_len = WIRE_HEADER_BYTES + len(body_bytes)
    if total_len > max_wire_cell_bytes:
        raise CryptoV3Error("oversize_wire_cell", f"{total_len} > {max_wire_cell_bytes}")
    hdr = _HEADER_STRUCT.pack(
        WIRE_MAGIC_V3,
        WIRE_VERSION_BYTE_V3,
        msg_type,
        flags,
        DIRECTION_TO_BYTE[direction],
        bundle_id,
        session_id,
        epoch,
        seq,
        len(body_bytes),
    )
    return hdr + body_bytes


def parse_frame_v3(packet: bytes, *, max_wire_cell_bytes: int = MAX_WIRE_CELL_BYTES) -> WireFrameV3:
    if not isinstance(packet, (bytes, bytearray)):
        raise CryptoV3Error("bad_packet_type")
    bb = bytes(packet)
    if len(bb) > max_wire_cell_bytes:
        raise CryptoV3Error("oversize_wire_cell", f"{len(bb)} > {max_wire_cell_bytes}")
    if len(bb) < WIRE_HEADER_BYTES + AEAD_TAG_BYTES:
        raise CryptoV3Error("truncated_frame")
    hdr = bb[:WIRE_HEADER_BYTES]
    magic, ver, msg_type, flags, dir_b, bundle_id, session_id, epoch, seq, body_len = (
        _HEADER_STRUCT.unpack(hdr)
    )
    if magic != WIRE_MAGIC_V3:
        raise CryptoV3Error("bad_magic")
    if ver != WIRE_VERSION_BYTE_V3:
        raise CryptoV3Error("bad_version")
    if msg_type not in VALID_MSG_TYPES:
        raise CryptoV3Error("bad_msg_type")
    if flags & ~VALID_FLAGS_MASK:
        raise CryptoV3Error("bad_flags")
    if dir_b not in BYTE_TO_DIRECTION:
        raise CryptoV3Error("bad_direction")
    if WIRE_HEADER_BYTES + body_len != len(bb):
        raise CryptoV3Error("frame_length_mismatch")
    return WireFrameV3(
        msg_type=msg_type,
        flags=flags,
        direction=BYTE_TO_DIRECTION[dir_b],
        bundle_id=bundle_id,
        session_id=session_id,
        epoch=epoch,
        seq=seq,
        header_bytes=hdr,
        body_bytes=bb[WIRE_HEADER_BYTES:],
    )


def seal_encrypted_header_v3(
    *,
    header_key: bytes,
    header_nonce: bytes,
    route_tag: bytes,
    bundle_id: bytes,
    session_id: bytes,
    epoch: int,
    seq: int,
    direction: str,
    msg_type: int,
    outer_header_aad: bytes,
) -> bytes:
    """Seal 48-byte inner header + prepend 16-byte route tag (80 bytes total)."""
    if len(route_tag) != 16:
        raise CryptoV3Error("bad_route_tag_len")
    inner_pt = _INNER_HEADER_STRUCT.pack(
        bundle_id,
        session_id,
        epoch,
        seq,
        DIRECTION_TO_BYTE[direction],
        msg_type,
        0,
    )
    enc_hdr = aead_seal(header_key, header_nonce, inner_pt, b"IDRE-V3-HDR|" + outer_header_aad)
    out = route_tag + enc_hdr
    assert len(out) == ENCRYPTED_HEADER_OVERHEAD_BYTES
    return out


def open_encrypted_header_v3(
    *,
    header_key: bytes,
    header_nonce: bytes,
    expected_route_tag: bytes,
    blob: bytes,
    outer_frame: WireFrameV3,
) -> bytes:
    """Validate route tag and decrypt 80-byte encrypted header prefix; return remaining body ciphertext."""
    if len(blob) < ENCRYPTED_HEADER_OVERHEAD_BYTES + AEAD_TAG_BYTES:
        raise CryptoV3Error("truncated_encrypted_header")
    got_tag = blob[:16]
    if not hmac.compare_digest(got_tag, expected_route_tag):
        raise CryptoV3Error("invalid_route_tag")
    enc_hdr = blob[16:ENCRYPTED_HEADER_OVERHEAD_BYTES]
    inner_pt = aead_open(
        header_key,
        header_nonce,
        enc_hdr,
        b"IDRE-V3-HDR|" + outer_frame.header_bytes,
    )
    if len(inner_pt) != _INNER_HEADER_STRUCT.size:
        raise CryptoV3Error("bad_inner_header_len")
    b_id, s_id, epoch, seq, dir_b, msg_type, pad = _INNER_HEADER_STRUCT.unpack(inner_pt)
    if (
        b_id != outer_frame.bundle_id
        or s_id != outer_frame.session_id
        or epoch != outer_frame.epoch
        or seq != outer_frame.seq
        or BYTE_TO_DIRECTION.get(dir_b) != outer_frame.direction
        or msg_type != outer_frame.msg_type
        or pad != 0
    ):
        raise CryptoV3Error("inner_header_mismatch")
    return blob[ENCRYPTED_HEADER_OVERHEAD_BYTES:]
