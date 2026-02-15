from __future__ import annotations

import json
from typing import Any, List, Tuple

MAC_LEN = 32


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def frame_payload(ct: List[int], tag: bytes, pad: List[int] | None = None) -> List[int]:
    """Wire payload: [ct_len][ct_bytes...][tag_bytes(32)...][pad/noise...]"""
    real_ct = [int(x) & 0xFF for x in ct]
    tag_bytes = [b for b in (tag or b"")]
    if len(tag_bytes) != MAC_LEN:
        raise ValueError("bad_tag_len")
    out = [len(real_ct)] + real_ct + tag_bytes
    if pad:
        out.extend([int(x) & 0xFF for x in pad])
    return out


def unframe_payload(framed: List[int]) -> Tuple[List[int], bytes]:
    if not framed:
        return [], b""
    n = int(framed[0])
    if n < 0:
        return [], b""
    ct = [int(x) & 0xFF for x in framed[1 : 1 + n]]
    tag_start = 1 + n
    tag_end = tag_start + MAC_LEN
    if tag_end > len(framed):
        return [], b""
    tag = bytes(int(x) & 0xFF for x in framed[tag_start:tag_end])
    return ct, tag

