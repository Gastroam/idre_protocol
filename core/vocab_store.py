from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple


MAGIC8 = b"IDRVOCB1"


@dataclass(frozen=True)
class VocabBin:
    tokens: List[str]
    vocab_id: bytes


def write_vocab_bin(*, tokens: List[str], vocab_id: bytes, out_path: str) -> None:
    if not isinstance(tokens, list) or not all(isinstance(t, str) for t in tokens):
        raise TypeError("tokens must be list[str]")
    vid = bytes(vocab_id)
    if not (1 <= len(vid) <= 64):
        raise ValueError("bad_vocab_id_len")

    # Encode tokens as UTF-8 and build offsets.
    blobs: List[bytes] = []
    offsets = [0]
    total = 0
    for t in tokens:
        b = t.encode("utf-8")
        blobs.append(b)
        total += len(b)
        offsets.append(total)

    if len(tokens) > 0xFFFFFFFF:
        raise ValueError("too_many_tokens")
    if total > 0xFFFFFFFF:
        raise ValueError("data_too_large")

    # Layout:
    # MAGIC8
    # u32 n_tokens
    # u16 vocab_id_len
    # vocab_id bytes
    # (n_tokens+1) * u32 offsets
    # data bytes
    hdr = bytearray()
    hdr += MAGIC8
    hdr += struct.pack(">I", len(tokens))
    hdr += struct.pack(">H", len(vid))
    hdr += vid
    for off in offsets:
        hdr += struct.pack(">I", int(off))

    outp = Path(out_path)
    outp.parent.mkdir(parents=True, exist_ok=True)
    with outp.open("wb") as f:
        f.write(hdr)
        for b in blobs:
            f.write(b)


def read_vocab_bin(path: str) -> VocabBin:
    p = Path(path)
    bb = p.read_bytes()
    if len(bb) < 8 + 4 + 2:
        raise ValueError("too_short")
    if bb[:8] != MAGIC8:
        raise ValueError("bad_magic")
    off = 8
    n = struct.unpack(">I", bb[off : off + 4])[0]
    off += 4
    vid_len = struct.unpack(">H", bb[off : off + 2])[0]
    off += 2
    if vid_len <= 0 or vid_len > 64:
        raise ValueError("bad_vocab_id_len")
    if off + vid_len > len(bb):
        raise ValueError("corrupt")
    vocab_id = bb[off : off + vid_len]
    off += vid_len

    # Offsets table.
    need = (int(n) + 1) * 4
    if off + need > len(bb):
        raise ValueError("corrupt")
    offsets = []
    for i in range(int(n) + 1):
        o = struct.unpack(">I", bb[off + (i * 4) : off + (i * 4) + 4])[0]
        offsets.append(int(o))
    off += need
    data = bb[off:]

    if offsets and offsets[-1] > len(data):
        raise ValueError("corrupt")

    toks: List[str] = []
    for i in range(int(n)):
        a = int(offsets[i])
        b = int(offsets[i + 1])
        if b < a or b > len(data):
            raise ValueError("corrupt")
        try:
            toks.append(data[a:b].decode("utf-8", errors="strict"))
        except Exception as exc:
            raise ValueError("bad_utf8") from exc
    return VocabBin(tokens=toks, vocab_id=bytes(vocab_id))

