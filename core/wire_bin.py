from __future__ import annotations

import json
import struct
from typing import Any, Dict, Tuple


MAGIC8 = b"IDREMSG1"  # 7 bytes + version, used as a sanity check (not security)

# Defensive caps: these blobs may be carried over the network.
# Keep header small (metadata only). Payload cap should align with your transport needs.
MAX_HEADER_LEN = 4096
MAX_PAYLOAD_LEN = 262_144
MAX_PREV_HOP_ID_LEN = 256


def pack_wire_message(msg: Dict[str, Any]) -> bytes:
    """
    Pack a Hive/IDRE message dict into a compact binary blob.

    Format:
      MAGIC8 (8)
      u32 header_len
      header_json (UTF-8, sorted keys)
      u32 payload_len
      payload_bytes

    Notes:
    - `payload` in msg is expected to be a list of ints 0..255.
    - For traffic-shaping, you will wrap this in fixed-size "cells" elsewhere.
    """
    if not isinstance(msg, dict):
        raise TypeError("msg must be dict")
    payload = msg.get("payload")
    if not isinstance(payload, list):
        raise ValueError("missing_payload")
    payload_bytes = bytes(int(x) & 0xFF for x in payload)

    header = dict(msg)
    header.pop("payload", None)
    header_json = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")

    if len(header_json) > 0xFFFFFFFF:
        raise ValueError("header_too_large")
    if len(payload_bytes) > 0xFFFFFFFF:
        raise ValueError("payload_too_large")

    return MAGIC8 + struct.pack(">I", len(header_json)) + header_json + struct.pack(">I", len(payload_bytes)) + payload_bytes


def unpack_wire_message(blob: bytes) -> Dict[str, Any]:
    if not isinstance(blob, (bytes, bytearray)):
        raise TypeError("blob must be bytes")
    bb = bytes(blob)
    if len(bb) < 8 + 4 + 4:
        raise ValueError("too_short")
    if bb[:8] != MAGIC8:
        raise ValueError("bad_magic")

    off = 8
    hlen = struct.unpack(">I", bb[off : off + 4])[0]
    off += 4
    if int(hlen) > int(MAX_HEADER_LEN):
        raise ValueError("header_too_large")
    if off + hlen + 4 > len(bb):
        raise ValueError("bad_header_len")
    header_json = bb[off : off + hlen]
    off += hlen
    try:
        header = json.loads(header_json.decode("utf-8"))
    except Exception as exc:
        raise ValueError("bad_header_json") from exc
    if not isinstance(header, dict):
        raise ValueError("bad_header_json")

    plen = struct.unpack(">I", bb[off : off + 4])[0]
    off += 4
    if int(plen) > int(MAX_PAYLOAD_LEN):
        raise ValueError("payload_too_large")
    if off + plen > len(bb):
        raise ValueError("bad_payload_len")
    payload_bytes = bb[off : off + plen]

    header["payload"] = [b for b in payload_bytes]
    return header


def pack_receive_envelope(prev_hop_id: str, msg: Dict[str, Any]) -> bytes:
    """Pack the minimum data needed to call /hive/v12/receive."""
    if not isinstance(prev_hop_id, str) or not prev_hop_id:
        raise ValueError("bad_prev_hop_id")
    if len(prev_hop_id.encode("utf-8")) > int(MAX_PREV_HOP_ID_LEN):
        raise ValueError("prev_hop_id_too_large")
    inner = pack_wire_message(msg)
    pid = prev_hop_id.encode("utf-8")
    if len(pid) > 65535:
        raise ValueError("prev_hop_id_too_large")
    return b"IDRERECV" + struct.pack(">H", len(pid)) + pid + inner


def unpack_receive_envelope(blob: bytes) -> Tuple[str, Dict[str, Any]]:
    if not isinstance(blob, (bytes, bytearray)):
        raise TypeError("blob must be bytes")
    bb = bytes(blob)
    if len(bb) < 8 + 2 + 8:
        raise ValueError("too_short")
    if bb[:8] != b"IDRERECV":
        raise ValueError("bad_magic")
    off = 8
    n = struct.unpack(">H", bb[off : off + 2])[0]
    off += 2
    if off + n > len(bb):
        raise ValueError("bad_prev_len")
    if int(n) > int(MAX_PREV_HOP_ID_LEN):
        raise ValueError("bad_prev_len")
    prev = bb[off : off + n].decode("utf-8")
    off += n
    msg = unpack_wire_message(bb[off:])
    return prev, msg
