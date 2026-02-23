from __future__ import annotations

import hashlib

from core.wire import frame_payload, unframe_payload

def test_wire_frame_unframe_roundtrip() -> None:
    ct = [i & 0xFF for i in range(200)]
    tag = hashlib.sha256(b"tag").digest()  # 32 bytes
    framed = frame_payload(ct, tag, pad=[0] * 16)
    ct2, tag2 = unframe_payload(framed)
    assert ct2 == ct
    assert tag2 == tag
