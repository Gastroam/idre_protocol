from __future__ import annotations

import struct

from core.cell import pack_cell, unpack_cell
from core.wire_bin import MAGIC8, pack_receive_envelope, pack_wire_message, unpack_receive_envelope, unpack_wire_message

def test_wire_bin_roundtrip() -> None:
    msg = {
        "type": "DATA",
        "field_profile_id": "deadbeefdeadbeef",
        "session_id": "a" * 32,
        "nonce": 1,
        "created_at_ms": 1,
        "expires_at_ms": 2,
        "src_node_id": "A",
        "dst_node_id": "B",
        "hop_count": 0,
        "max_hops": 8,
        "payload": [i & 0xFF for i in range(100)],
    }
    blob = pack_wire_message(msg)
    out = unpack_wire_message(blob)
    assert out == msg

def test_receive_envelope_roundtrip() -> None:
    msg = {"type": "DATA", "payload": [1, 2, 3]}
    blob = pack_receive_envelope("A", msg)
    prev, out = unpack_receive_envelope(blob)
    assert prev == "A"
    assert out == msg

def test_cell_fixed_size_and_unpack() -> None:
    inner = b"hello"
    cell = pack_cell(inner=inner, cell_len=128)
    assert isinstance(cell, (bytes, bytearray))
    assert len(cell) == 128
    out = unpack_cell(cell)
    assert out.inner == inner

def test_wire_bin_header_len_cap_rejects() -> None:
    # Large header length should be rejected before slicing/parsing JSON.
    blob = MAGIC8 + struct.pack(">I", 0xFFFFFFFF) + struct.pack(">I", 0)
    try:
        unpack_wire_message(blob)
        assert False, "expected error"
    except ValueError as exc:
        assert "header_too_large" in str(exc)

def test_wire_bin_payload_len_cap_rejects() -> None:
    # Construct a minimal valid JSON header, then an oversized plen.
    header_json = b"{}"
    blob = MAGIC8 + struct.pack(">I", len(header_json)) + header_json + struct.pack(">I", 0xFFFFFFFF) + b""
    try:
        unpack_wire_message(blob)
        assert False, "expected error"
    except ValueError as exc:
        assert "payload_too_large" in str(exc)
