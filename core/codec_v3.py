"""IDRE v3 Strict Codec Framing (Task 6 — M1 strict literal opcode; adaptive dict in Task 9).

Core dependency rule: Python standard library only.
"""

from __future__ import annotations

import struct

OP_LITERAL_V3 = 0x00


class CodecV3Error(ValueError):
    """Raised on malformed, truncated, oversize, or disallowed v3 codec streams."""

    def __init__(self, reason: str, message: str = "") -> None:
        self.reason = reason
        super().__init__(message or reason)


def pack_strict_stream_v3(vocab_blob: bytes, *, max_plaintext_bytes: int) -> bytes:
    """Pack a strict vocabulary blob into a single OP_LITERAL_V3 frame: [0x00][u16 len][blob]."""
    if not isinstance(vocab_blob, (bytes, bytearray)):
        raise CodecV3Error("bad_type", "vocab_blob must be bytes")
    bb = bytes(vocab_blob)
    if len(bb) > max_plaintext_bytes:
        raise CodecV3Error("oversize_payload", f"{len(bb)} > {max_plaintext_bytes}")
    if len(bb) > 0xFFFF:
        raise CodecV3Error("oversize_payload", "vocab_blob exceeds u16 length")
    return struct.pack(">B H", OP_LITERAL_V3, len(bb)) + bb


def unpack_strict_stream_v3(stream: bytes, *, max_plaintext_bytes: int) -> bytes:
    """Strictly unpack an M1 OP_LITERAL_V3 stream, rejecting unknown opcodes or trailing bytes."""
    if not isinstance(stream, (bytes, bytearray)):
        raise CodecV3Error("bad_type", "stream must be bytes")
    bb = bytes(stream)
    if len(bb) < 3:
        raise CodecV3Error("truncated_stream", "stream shorter than 3-byte opcode header")
    opcode, length = struct.unpack(">B H", bb[:3])
    if opcode != OP_LITERAL_V3:
        raise CodecV3Error("unsupported_opcode", f"disallowed opcode 0x{opcode:02x} in strict M1 mode")
    if length > max_plaintext_bytes:
        raise CodecV3Error("oversize_payload", f"declared length {length} > {max_plaintext_bytes}")
    expected_total = 3 + length
    if len(bb) < expected_total:
        raise CodecV3Error("truncated_stream", f"expected {expected_total} bytes, got {len(bb)}")
    if len(bb) > expected_total:
        raise CodecV3Error("trailing_garbage", f"{len(bb) - expected_total} trailing bytes")
    return bb[3:expected_total]
