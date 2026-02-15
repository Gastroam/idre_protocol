from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass
from typing import Optional, Tuple


CELL_MAGIC8 = b"IDRCELL1"


@dataclass(frozen=True)
class Cell:
    inner: bytes  # caller-defined opaque payload (often a packed receive envelope)


def pack_cell(*, inner: bytes, cell_len: int) -> bytes:
    """
    Fixed-size cell container.

    Format (all bytes, fixed total length == cell_len):
      MAGIC8 (8)
      u16 inner_len
      inner bytes
      random padding

    Notes:
    - Padding is random to avoid static patterns.
    - This container is NOT cryptographic security; it is for constant-size transport.
    """
    if not isinstance(inner, (bytes, bytearray)):
        raise TypeError("inner must be bytes")
    inner_b = bytes(inner)
    if cell_len < 8 + 2:
        raise ValueError("cell_len_too_small")
    if len(inner_b) > (cell_len - 10):
        raise ValueError("inner_too_large")
    pad_len = int(cell_len) - 10 - len(inner_b)
    pad = secrets.token_bytes(pad_len) if pad_len > 0 else b""
    return CELL_MAGIC8 + struct.pack(">H", len(inner_b)) + inner_b + pad


def unpack_cell(blob: bytes) -> Cell:
    if not isinstance(blob, (bytes, bytearray)):
        raise TypeError("blob must be bytes")
    bb = bytes(blob)
    if len(bb) < 10:
        raise ValueError("too_short")
    if bb[:8] != CELL_MAGIC8:
        raise ValueError("bad_magic")
    n = struct.unpack(">H", bb[8:10])[0]
    if 10 + n > len(bb):
        raise ValueError("bad_inner_len")
    inner = bb[10 : 10 + n]
    return Cell(inner=inner)


def maybe_unpack_cell(blob: bytes) -> Tuple[bool, Optional[Cell]]:
    try:
        return True, unpack_cell(blob)
    except Exception:
        return False, None

