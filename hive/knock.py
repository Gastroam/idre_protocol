"""
IDRE Knock — Single Packet Authorization (SPA) for Dark Mode.

Knock key is derived from the field fingerprint bits so that only
nodes sharing the same field configuration can authorize each other.
No new secrets to provision.

Knock packet layout (55 bytes, fixed size):
  [MAGIC: b"IDRKNK1" (7B)] [timestamp_ms (8B)] [nonce (8B)] [tag (32B)]

tag = HMAC-SHA256(knock_key, timestamp_ms || nonce)
knock_key = SHA256("KNOCK/" || bytes(bits) || epoch.to_bytes(8))
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
import time
from typing import List, Optional, Tuple

KNOCK_MAGIC = b"IDRKNK1"
KNOCK_LEN = 7 + 8 + 8 + 32  # 55 bytes


def derive_knock_key(bits: List[int], epoch: int) -> bytes:
    """Derive a knock key from field fingerprint bits and epoch.
    
    Ties SPA authentication to the same field configuration used for
    encryption — no separate knock secret needed.
    """
    bits_bytes = bytes(int(b) & 1 for b in bits)
    return hashlib.sha256(
        b"KNOCK/" + bits_bytes + int(epoch).to_bytes(8, "big")
    ).digest()


def create_knock(bits: List[int], *, epoch: Optional[int] = None) -> bytes:
    """Create a 55-byte knock packet.
    
    Args:
        bits: Field fingerprint bits (shared secret).
        epoch: Optional epoch counter. Defaults to current time // 60
               (1-minute epochs).
    
    Returns:
        55-byte knock packet ready to send over UDP.
    """
    if epoch is None:
        epoch = int(time.time()) // 60

    key = derive_knock_key(bits, epoch)
    ts_ms = int(time.time() * 1000)
    nonce = secrets.token_bytes(8)

    # tag = HMAC-SHA256(key, timestamp || nonce)
    msg = struct.pack(">Q", ts_ms) + nonce
    tag = hmac.new(key, msg, hashlib.sha256).digest()

    pkt = bytearray()
    pkt += KNOCK_MAGIC
    pkt += struct.pack(">Q", ts_ms)
    pkt += nonce
    pkt += tag
    assert len(pkt) == KNOCK_LEN
    return bytes(pkt)


def verify_knock(
    data: bytes,
    bits: List[int],
    *,
    epoch: Optional[int] = None,
    skew_ms: int = 30_000,
) -> Tuple[bool, str]:
    """Verify a knock packet.
    
    Args:
        data: Raw bytes received.
        bits: Field fingerprint bits.
        epoch: Current epoch. Defaults to time.time() // 60.
        skew_ms: Maximum clock skew tolerance in ms (default 30s).
    
    Returns:
        (valid, reason) tuple. reason is "" on success.
    """
    if len(data) != KNOCK_LEN:
        return False, "bad_length"

    if data[:7] != KNOCK_MAGIC:
        return False, "bad_magic"

    ts_ms = struct.unpack(">Q", data[7:15])[0]
    nonce = data[15:23]
    received_tag = data[23:55]

    # Check timestamp within skew
    now_ms = int(time.time() * 1000)
    if abs(now_ms - ts_ms) > skew_ms:
        return False, "expired"

    # Try current epoch ±1 to handle epoch boundaries
    if epoch is None:
        epoch = int(time.time()) // 60

    msg = struct.pack(">Q", ts_ms) + nonce

    for ep in (epoch, epoch - 1, epoch + 1):
        key = derive_knock_key(bits, ep)
        expected_tag = hmac.new(key, msg, hashlib.sha256).digest()
        if hmac.compare_digest(received_tag, expected_tag):
            return True, ""

    return False, "bad_tag"


__all__ = [
    "KNOCK_MAGIC",
    "KNOCK_LEN",
    "derive_knock_key",
    "create_knock",
    "verify_knock",
]
