import hashlib
import json
import time
import struct
from typing import Any, Dict, List, Tuple

MAC_LEN = 32
DEFAULT_MAX_CT_LEN = 100_000

# Added constants
DEFAULT_MAX_PAYLOAD_INTS = 4096
DEFAULT_MAX_BODY_BYTES = 2_000_000
DEFAULT_CHALLENGE_TTL_MS = 30_000
DEFAULT_SKEW_MS = 120_000
DEFAULT_MAX_TTL_MS = 600_000
DEFAULT_DEFAULT_TTL_MS = 60_000
DEFAULT_MAX_PENDING_CHALLENGES = 8192

RESONANT_SIGNATURE = (
    "Ghost cursors trace the contours of cognition within a shared resonant chamber of quantized awareness."
)

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def zlib_crc32(data: bytes) -> int:
    import zlib
    return zlib.crc32(data) & 0xFFFFFFFF

def _crc32(data: bytes) -> int:
    return int(zlib_crc32(data))

def _now_ms() -> int:
    return int(time.time() * 1000.0)

def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def compute_field_profile_id(profile: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(profile)).hexdigest()[:16]

def _expand_bytes(seed: bytes, n: int, domain: bytes) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        out.extend(_sha256(domain + seed + counter.to_bytes(4, "big")))
        counter += 1
    return bytes(out[:n])

def frame_payload(ct: List[int], tag: bytes, pad_bytes: int = 0) -> List[int]:
    real_ct = [int(x) & 0xFF for x in ct]
    tag_bytes = [b for b in (tag or b"")]
    if len(tag_bytes) != MAC_LEN:
        raise ValueError("bad_tag_len")

    n = len(real_ct)
    n_bytes = [(n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]
    framed = n_bytes + real_ct + tag_bytes
    if pad_bytes > 0:
        pad = _expand_bytes(_sha256(bytes(real_ct)), int(pad_bytes), b"PAD/")
        framed.extend([b for b in pad])
    return framed

def unframe_payload(framed: List[int], *, max_ct_len: int = DEFAULT_MAX_CT_LEN) -> Tuple[List[int], bytes]:
    if not framed or len(framed) < 4:
        return [], b""
    n = (framed[0] << 24) | (framed[1] << 16) | (framed[2] << 8) | framed[3]
    if n < 0:
        return [], b""
    if n > int(max_ct_len):
        return [], b""
    ct = [int(x) & 0xFF for x in framed[4 : 4 + n]]
    tag_start = 4 + n
    tag_end = tag_start + MAC_LEN
    if tag_end > len(framed):
        return [], b""
    tag = bytes(int(x) & 0xFF for x in framed[tag_start:tag_end])
    return ct, tag

def pack_plaintext(message: str) -> bytes:
    payload = (message or "").encode("utf-8")
    if len(payload) > 65535:
        raise ValueError("message_too_large")
    header = struct.pack(">HI", len(payload), zlib_crc32(payload))
    return header + payload

def unpack_plaintext(blob: bytes) -> Tuple[bool, str]:
    if len(blob) < 6:
        return False, ""
    n, crc = struct.unpack(">HI", blob[:6])
    data = blob[6 : 6 + int(n)]
    if len(data) != int(n):
        return False, ""
    if zlib_crc32(data) != int(crc):
        return False, ""
    try:
        return True, data.decode("utf-8", errors="strict")
    except Exception:
        return False, ""
