"""IDRE v3 Strict and Bounded Adaptive Dictionary Codec (Tasks 6 & 9).

Opcode grammar:
- `OP_LITERAL_V3 = 0x00`: `[0x00][u16 len][vocab_blob]`
- `OP_PROPOSE_V3 = 0x01`: `[0x01][16B label_id][u16 len][vocab_blob]`
- `OP_RECALL_V3  = 0x02`: `[0x02][16B label_id]`
- `OP_EVICT_V3   = 0x04`: `[0x04][16B label_id]`

Enforces receiver-side and sender-side bounds:
- 128-bit HMAC-SHA-256 labels keyed by stable directional `dict_key`
- At most 512 active entries and 128 KiB active payload bytes (LRU eviction)
- Rejects label-ID mismatches, conflicting label collisions (never overwrites),
  unknown recalls, unknown opcodes, truncated operands, and trailing garbage.

Core dependency rule: Python standard library only.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass
from typing import Optional, Tuple

OP_LITERAL_V3 = 0x00
OP_PROPOSE_V3 = 0x01
OP_RECALL_V3 = 0x02
OP_EVICT_V3 = 0x04

LABEL_ID_BYTES_V3 = 16  # 128-bit labels
MAX_DICT_ENTRIES_V3 = 512
MAX_DICT_BYTES_V3 = 128 * 1024  # 128 KiB
MAX_OBS_TRACKED_V3 = 256
MIN_OBS_FOR_PROPOSE_V3 = 3

DICT_STATE_MAGIC = b"IDRC3\x00"


class CodecV3Error(ValueError):
    """Raised on malformed, truncated, oversize, or disallowed v3 codec streams."""

    def __init__(self, reason: str, message: str = "") -> None:
        self.reason = reason
        super().__init__(message or reason)


def derive_label_id_v3(dict_key: bytes, vocab_blob: bytes) -> bytes:
    """Derive a 128-bit (16-byte) deterministic directional dictionary label."""
    if not isinstance(dict_key, (bytes, bytearray)) or len(dict_key) != 32:
        raise CodecV3Error("bad_dict_key", "dict_key must be 32 bytes")
    return hmac.new(bytes(dict_key), b"IDRE-V3-DICT-LABEL|" + bytes(vocab_blob), hashlib.sha256).digest()[
        :LABEL_ID_BYTES_V3
    ]


@dataclass(frozen=True)
class DictStateV3:
    """Immutable bounded adaptive dictionary state for one session direction."""

    # Ordered LRU: oldest first, most recently used last.
    entries: Tuple[Tuple[bytes, bytes], ...] = ()
    obs_counts: Tuple[Tuple[bytes, int], ...] = ()

    def __post_init__(self) -> None:
        if len(self.entries) > MAX_DICT_ENTRIES_V3:
            raise CodecV3Error("dict_entry_cap_exceeded")
        seen = set()
        total_b = 0
        for lid, data in self.entries:
            if len(lid) != LABEL_ID_BYTES_V3:
                raise CodecV3Error("bad_label_id_len")
            if lid in seen:
                raise CodecV3Error("duplicate_label_id")
            seen.add(lid)
            total_b += len(data)
        if total_b > MAX_DICT_BYTES_V3:
            raise CodecV3Error("dict_byte_cap_exceeded")
        if len(self.obs_counts) > MAX_OBS_TRACKED_V3:
            raise CodecV3Error("obs_cap_exceeded")

    @property
    def total_bytes(self) -> int:
        return sum(len(data) for _, data in self.entries)

    def lookup(self, label_id: bytes) -> Optional[bytes]:
        for lid, data in self.entries:
            if lid == label_id:
                return data
        return None

    def touch(self, label_id: bytes) -> "DictStateV3":
        kept = []
        target = None
        for item in self.entries:
            if item[0] == label_id:
                target = item
            else:
                kept.append(item)
        if target is None:
            raise CodecV3Error("unknown_recall_id")
        kept.append(target)
        return DictStateV3(entries=tuple(kept), obs_counts=self.obs_counts)

    def insert_lru(self, label_id: bytes, data: bytes) -> "DictStateV3":
        if len(label_id) != LABEL_ID_BYTES_V3:
            raise CodecV3Error("bad_label_id_len")
        if len(data) > MAX_DICT_BYTES_V3:
            raise CodecV3Error("dict_entry_too_large")
        existing = self.lookup(label_id)
        if existing is not None:
            if existing != data:
                raise CodecV3Error("conflicting_label_collision")
            return self.touch(label_id)

        items = list(self.entries)
        total = sum(len(d) for _, d in items)
        while items and (len(items) >= MAX_DICT_ENTRIES_V3 or total + len(data) > MAX_DICT_BYTES_V3):
            _, evicted = items.pop(0)
            total -= len(evicted)
        items.append((label_id, data))

        # Clear observation count once promoted
        new_obs = tuple((k, c) for k, c in self.obs_counts if k != label_id)
        return DictStateV3(entries=tuple(items), obs_counts=new_obs)

    def evict(self, label_id: bytes) -> "DictStateV3":
        kept = tuple(item for item in self.entries if item[0] != label_id)
        if len(kept) == len(self.entries):
            raise CodecV3Error("unknown_evict_id")
        return DictStateV3(entries=kept, obs_counts=self.obs_counts)

    def bump_observation(self, label_id: bytes) -> Tuple["DictStateV3", int]:
        obs_list = list(self.obs_counts)
        for i, (k, c) in enumerate(obs_list):
            if k == label_id:
                new_c = c + 1
                obs_list.pop(i)
                obs_list.append((label_id, new_c))
                return DictStateV3(entries=self.entries, obs_counts=tuple(obs_list)), new_c
        if len(obs_list) >= MAX_OBS_TRACKED_V3:
            obs_list.pop(0)
        obs_list.append((label_id, 1))
        return DictStateV3(entries=self.entries, obs_counts=tuple(obs_list)), 1


def encode_dict_state_v3(state: DictStateV3) -> bytes:
    out = bytearray(DICT_STATE_MAGIC)
    out.extend(struct.pack(">H H", len(state.entries), len(state.obs_counts)))
    for lid, data in state.entries:
        out.extend(lid)
        out.extend(struct.pack(">H", len(data)))
        out.extend(data)
    for lid, count in state.obs_counts:
        out.extend(lid)
        out.extend(struct.pack(">I", count))
    return bytes(out)


def decode_dict_state_v3(raw: bytes) -> DictStateV3:
    bb = bytes(raw)
    if len(bb) < len(DICT_STATE_MAGIC) + 4:
        raise CodecV3Error("truncated_dict_state")
    if bb[: len(DICT_STATE_MAGIC)] != DICT_STATE_MAGIC:
        raise CodecV3Error("bad_dict_state_magic")
    off = len(DICT_STATE_MAGIC)
    n_entries, n_obs = struct.unpack(">H H", bb[off : off + 4])
    off += 4
    if n_entries > MAX_DICT_ENTRIES_V3 or n_obs > MAX_OBS_TRACKED_V3:
        raise CodecV3Error("dict_state_cap_exceeded")
    entries = []
    for _ in range(n_entries):
        if off + LABEL_ID_BYTES_V3 + 2 > len(bb):
            raise CodecV3Error("truncated_dict_state")
        lid = bb[off : off + LABEL_ID_BYTES_V3]
        off += LABEL_ID_BYTES_V3
        (dlen,) = struct.unpack(">H", bb[off : off + 2])
        off += 2
        if off + dlen > len(bb):
            raise CodecV3Error("truncated_dict_state")
        entries.append((lid, bb[off : off + dlen]))
        off += dlen
    obs = []
    for _ in range(n_obs):
        if off + LABEL_ID_BYTES_V3 + 4 > len(bb):
            raise CodecV3Error("truncated_dict_state")
        lid = bb[off : off + LABEL_ID_BYTES_V3]
        off += LABEL_ID_BYTES_V3
        (cnt,) = struct.unpack(">I", bb[off : off + 4])
        off += 4
        obs.append((lid, int(cnt)))
    if off != len(bb):
        raise CodecV3Error("trailing_bytes_in_dict_state")
    return DictStateV3(entries=tuple(entries), obs_counts=tuple(obs))


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


def pack_adaptive_stream_v3(
    vocab_blob: bytes,
    *,
    dict_state: DictStateV3,
    dict_key: bytes,
    max_plaintext_bytes: int,
) -> Tuple[bytes, DictStateV3, int]:
    """Purely encode `vocab_blob` using bounded adaptive dictionary learning.

    Returns `(stream_bytes, candidate_next_dict_state, emitted_opcode)`.
    """
    bb = bytes(vocab_blob)
    if len(bb) > max_plaintext_bytes:
        raise CodecV3Error("oversize_payload", f"{len(bb)} > {max_plaintext_bytes}")
    label_id = derive_label_id_v3(dict_key, bb)

    existing = dict_state.lookup(label_id)
    if existing is not None:
        if existing != bb:
            # Collision fallback: never emit a false recall
            return pack_strict_stream_v3(bb, max_plaintext_bytes=max_plaintext_bytes), dict_state, OP_LITERAL_V3
        stream = struct.pack(">B", OP_RECALL_V3) + label_id
        return stream, dict_state.touch(label_id), OP_RECALL_V3

    bumped_state, count = dict_state.bump_observation(label_id)
    propose_len = 1 + LABEL_ID_BYTES_V3 + 2 + len(bb)
    if count >= MIN_OBS_FOR_PROPOSE_V3 and propose_len <= max_plaintext_bytes + 3:
        stream = struct.pack(">B", OP_PROPOSE_V3) + label_id + struct.pack(">H", len(bb)) + bb
        next_state = bumped_state.insert_lru(label_id, bb)
        return stream, next_state, OP_PROPOSE_V3

    return pack_strict_stream_v3(bb, max_plaintext_bytes=max_plaintext_bytes), bumped_state, OP_LITERAL_V3


def unpack_adaptive_stream_v3(
    stream: bytes,
    *,
    dict_state: DictStateV3,
    dict_key: bytes,
    max_plaintext_bytes: int,
) -> Tuple[bytes, DictStateV3, int]:
    """Strictly decode an adaptive v3 stream and return `(vocab_blob, next_dict_state, opcode)`.

    Any invalid opcode, truncated operand, trailing garbage, label mismatch,
    conflicting collision, unknown recall, or cap violation raises `CodecV3Error`
    without mutating `dict_state`.
    """
    if not isinstance(stream, (bytes, bytearray)):
        raise CodecV3Error("bad_type")
    bb = bytes(stream)
    if len(bb) < 1:
        raise CodecV3Error("truncated_stream")
    opcode = bb[0]

    if opcode == OP_LITERAL_V3:
        blob = unpack_strict_stream_v3(bb, max_plaintext_bytes=max_plaintext_bytes)
        return blob, dict_state, OP_LITERAL_V3

    if opcode == OP_PROPOSE_V3:
        hdr_len = 1 + LABEL_ID_BYTES_V3 + 2
        if len(bb) < hdr_len:
            raise CodecV3Error("truncated_stream")
        label_id = bb[1 : 1 + LABEL_ID_BYTES_V3]
        (dlen,) = struct.unpack(">H", bb[1 + LABEL_ID_BYTES_V3 : hdr_len])
        if dlen > max_plaintext_bytes:
            raise CodecV3Error("oversize_payload")
        expected_total = hdr_len + dlen
        if len(bb) < expected_total:
            raise CodecV3Error("truncated_stream")
        if len(bb) > expected_total:
            raise CodecV3Error("trailing_garbage")
        blob = bb[hdr_len:expected_total]
        expected_id = derive_label_id_v3(dict_key, blob)
        if not hmac.compare_digest(label_id, expected_id):
            raise CodecV3Error("label_id_mismatch")
        next_state = dict_state.insert_lru(label_id, blob)
        return blob, next_state, OP_PROPOSE_V3

    if opcode == OP_RECALL_V3:
        expected_total = 1 + LABEL_ID_BYTES_V3
        if len(bb) < expected_total:
            raise CodecV3Error("truncated_stream")
        if len(bb) > expected_total:
            raise CodecV3Error("trailing_garbage")
        label_id = bb[1:expected_total]
        blob = dict_state.lookup(label_id)
        if blob is None:
            raise CodecV3Error("unknown_recall_id")
        if len(blob) > max_plaintext_bytes:
            raise CodecV3Error("oversize_payload")
        return blob, dict_state.touch(label_id), OP_RECALL_V3

    raise CodecV3Error("unsupported_opcode", f"unknown opcode 0x{opcode:02x}")
