"""Tests for Task 9: Bounded adaptive dictionary grammar, collisions, caps, and parser rejections."""

from __future__ import annotations

import struct

import pytest

from core.codec_v3 import (
    MAX_DICT_BYTES_V3,
    MAX_DICT_ENTRIES_V3,
    OP_LITERAL_V3,
    OP_PROPOSE_V3,
    OP_RECALL_V3,
    CodecV3Error,
    DictStateV3,
    decode_dict_state_v3,
    derive_label_id_v3,
    encode_dict_state_v3,
    pack_adaptive_stream_v3,
    unpack_adaptive_stream_v3,
)


def test_adaptive_parser_rejects_malformed_and_preserves_state():
    key = b"\x55" * 32
    ds = DictStateV3()
    blob = b"hello-vocab-blob"
    lid = derive_label_id_v3(key, blob)

    # Pre-populate one entry for collision/recall checks
    ds_populated = ds.insert_lru(lid, blob)
    snap = encode_dict_state_v3(ds_populated)
    assert decode_dict_state_v3(snap) == ds_populated

    bad_streams = [
        ("truncated_stream", b""),
        ("unsupported_opcode", b"\x99\x00\x01a"),
        ("truncated_stream", struct.pack(">B", OP_PROPOSE_V3) + lid[:4]),
        ("trailing_garbage", struct.pack(">B", OP_RECALL_V3) + lid + b"\xff"),
        ("unknown_recall_id", struct.pack(">B", OP_RECALL_V3) + (b"\x00" * 16)),
        (
            "label_id_mismatch",
            struct.pack(">B", OP_PROPOSE_V3) + (b"\x11" * 16) + struct.pack(">H", len(blob)) + blob,
        ),
        (
            "oversize_payload",
            struct.pack(">B", OP_PROPOSE_V3) + lid + struct.pack(">H", 200) + (b"x" * 200),
        ),
    ]
    for expected_reason, stream in bad_streams:
        with pytest.raises(CodecV3Error) as exc_info:
            unpack_adaptive_stream_v3(
                stream, dict_state=ds_populated, dict_key=key, max_plaintext_bytes=128
            )
        assert exc_info.value.reason == expected_reason
        assert encode_dict_state_v3(ds_populated) == snap

    # Conflicting label collision (same ID, different bytes) must NOT overwrite live meaning
    with pytest.raises(CodecV3Error) as exc_col:
        ds_populated.insert_lru(lid, b"different-bytes")
    assert exc_col.value.reason == "conflicting_label_collision"


def test_lru_entry_and_byte_caps_enforced():
    key = b"\x66" * 32
    ds = DictStateV3()

    # Fill past MAX_DICT_ENTRIES_V3 -> LRU evicts oldest, never exceeds 512 entries
    for i in range(MAX_DICT_ENTRIES_V3 + 10):
        data = f"entry-{i:04d}".encode("ascii")
        lid = derive_label_id_v3(key, data)
        ds = ds.insert_lru(lid, data)
    assert len(ds.entries) == MAX_DICT_ENTRIES_V3
    assert ds.total_bytes <= MAX_DICT_BYTES_V3

    # Large entries enforce MAX_DICT_BYTES_V3 (128 KiB)
    ds2 = DictStateV3()
    chunk_size = 4000
    for i in range(40):  # 160 KiB > 128 KiB
        data = struct.pack(">I", i) + (b"A" * (chunk_size - 4))
        lid = derive_label_id_v3(key, data)
        ds2 = ds2.insert_lru(lid, data)
    assert ds2.total_bytes <= MAX_DICT_BYTES_V3
    assert len(ds2.entries) == MAX_DICT_BYTES_V3 // chunk_size


def test_observation_proposal_and_recall_lifecycle():
    key = b"\x77" * 32
    ds = DictStateV3()
    blob = b"repeated-vocab-blob-payload"

    # Observations 1 and 2 emit OP_LITERAL_V3
    for _ in range(2):
        stream, ds, op = pack_adaptive_stream_v3(blob, dict_state=ds, dict_key=key, max_plaintext_bytes=4023)
        assert op == OP_LITERAL_V3

    # Observation 3 emits OP_PROPOSE_V3 and inserts into candidate state
    stream3, ds, op3 = pack_adaptive_stream_v3(blob, dict_state=ds, dict_key=key, max_plaintext_bytes=4023)
    assert op3 == OP_PROPOSE_V3

    # Next send emits 17-byte OP_RECALL_V3
    stream4, ds_after, op4 = pack_adaptive_stream_v3(blob, dict_state=ds, dict_key=key, max_plaintext_bytes=4023)
    assert op4 == OP_RECALL_V3
    assert len(stream4) == 17
    decoded, _, dec_op = unpack_adaptive_stream_v3(
        stream4, dict_state=ds, dict_key=key, max_plaintext_bytes=4023
    )
    assert dec_op == OP_RECALL_V3
    assert decoded == blob
