from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

from .vocab_store import read_vocab_bin


MAGIC8 = b"IDREVOC1"

# Defensive caps (codec is fed by decrypted bytes; still treat as untrusted to avoid bombs).
MAX_BLOB_BYTES = 2_000_000
MAX_TEXT_BYTES = 1_048_576
MAX_LITERAL_BYTES = 65535  # u16 length
MAX_VOCAB_ID_LEN = 64


@dataclass(frozen=True)
class Vocab:
    tokens: List[str]
    token_to_index: Dict[str, int]
    vocab_id: bytes  # 16 bytes by default (sha256(... )[:16])
    lens_by_first_char: Dict[str, List[int]]


def _canonical_json(obj) -> bytes:
    # Keep consistent with other repo code: stable separators, sorted keys where applicable.
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _compute_vocab_id(tokens: List[str]) -> bytes:
    # Order matters for positional vocab. This id is for mismatch detection, not a crypto claim.
    #
    # Implementation detail: avoid building an enormous JSON blob in memory for large vocabs.
    # We hash the exact bytes of: json.dumps(tokens, sort_keys=True, separators=(",", ":")).encode("utf-8")
    # For lists, sort_keys is irrelevant; default ensure_ascii=True is relied upon.
    hasher = hashlib.sha256()
    hasher.update(b"[")
    first = True
    for t in tokens:
        if not first:
            hasher.update(b",")
        first = False
        hasher.update(json.dumps(t, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))
    hasher.update(b"]")
    return hasher.digest()[:16]


def load_vocab(path: str) -> Vocab:
    p = Path(path)
    if p.suffix.lower() == ".bin":
        vb = read_vocab_bin(str(p))
        tokens = list(vb.tokens)
        vocab_id = bytes(vb.vocab_id)
    elif p.suffix.lower() == ".jsonl":
        tokens = []
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    t = json.loads(line)
                    if not isinstance(t, str):
                        continue # Skip non-string lines or raise? Let's skip for robustness
                    tokens.append(t)
                except json.JSONDecodeError:
                    continue
        vocab_id = _compute_vocab_id(tokens)
    else:
        raw = p.read_bytes()
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ValueError("bad_vocab_json") from exc
        if not isinstance(data, list) or not all(isinstance(x, str) for x in data):
            raise ValueError("bad_vocab_schema")
        tokens = list(data)
        vocab_id = _compute_vocab_id(tokens)

    token_to_index: Dict[str, int] = {}
    for i, t in enumerate(tokens):
        # First occurrence wins (deterministic); duplicates degrade compression but still decode correctly.
        if t not in token_to_index:
            token_to_index[t] = int(i)
    lens_by_first_char: Dict[str, List[int]] = {}
    for t in token_to_index.keys():
        if not t:
            continue
        c0 = t[0]
        lens_by_first_char.setdefault(c0, []).append(len(t))
    for c, lens in list(lens_by_first_char.items()):
        # unique, longest-first
        lens_by_first_char[c] = sorted(set(int(x) for x in lens), reverse=True)
    return Vocab(tokens=tokens, token_to_index=token_to_index, vocab_id=vocab_id, lens_by_first_char=lens_by_first_char)


def load_vocab_registry(paths: List[str]) -> Tuple[Dict[bytes, Vocab], Vocab]:
    """Load one or more vocab files and return (registry, default_vocab).

    - Registry is keyed by vocab_id bytes.
    - Default vocab is the last one in `paths` (treat as "latest").
    """
    if not isinstance(paths, list) or not paths or not all(isinstance(p, str) for p in paths):
        raise ValueError("bad_vocab_paths")
    reg: Dict[bytes, Vocab] = {}
    default: Vocab | None = None
    for p in paths:
        v = load_vocab(str(p))
        reg[bytes(v.vocab_id)] = v
        default = v
    assert default is not None
    return reg, default


def peek_vocab_id(blob: bytes) -> Tuple[bool, str, bytes]:
    """Parse the vocab_id out of an IDREVOC1 blob without decoding the stream."""
    if not isinstance(blob, (bytes, bytearray)):
        return False, "bad_type", b""
    bb = bytes(blob)
    if len(bb) > MAX_BLOB_BYTES:
        return False, "blob_too_large", b""
    if len(bb) < 8 + 1 + 1 + 2:
        return False, "too_short", b""
    if bb[:8] != MAGIC8:
        return False, "bad_magic", b""
    off = 8 + 1 + 1
    vid_len = struct.unpack(">H", bb[off : off + 2])[0]
    off += 2
    if int(vid_len) <= 0 or int(vid_len) > int(MAX_VOCAB_ID_LEN):
        return False, "bad_vocab_id_len", b""
    if off + int(vid_len) > len(bb):
        return False, "corrupt", b""
    return True, "ok", bytes(bb[off : off + int(vid_len)])


def encode_text(text: str, vocab: Vocab, *, allow_literals: bool = True) -> bytes:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    if not isinstance(vocab, Vocab):
        raise TypeError("vocab must be Vocab")

    tokens = vocab.tokens
    index_width = 2 if len(tokens) <= 65535 else 4
    if index_width not in (2, 4):
        raise ValueError("bad_index_width")

    def _match_len_at(i: int) -> int:
        if i >= len(text):
            return 0
        c0 = text[i]
        lens = vocab.lens_by_first_char.get(c0)
        if not lens:
            return 0
        for L in lens:
            j = i + int(L)
            if j <= len(text) and text[i:j] in vocab.token_to_index:
                return int(L)
        return 0

    out = bytearray()
    out += MAGIC8
    out += struct.pack(">B", index_width)

    allow_literals_used = 0
    # flags (bit0: literals were used)
    out += b"\x00"

    vid = bytes(vocab.vocab_id)
    out += struct.pack(">H", len(vid))
    out += vid

    i = 0
    while i < len(text):
        L = _match_len_at(i)
        if L > 0:
            seg = text[i : i + L]
            idx = vocab.token_to_index.get(seg)
            if idx is None:
                # should not happen, but keep deterministic behavior
                L = 0
            else:
                out += b"\x01"
                if index_width == 2:
                    if idx > 0xFFFF:
                        raise ValueError("token_index_too_large")
                    out += struct.pack(">H", int(idx))
                else:
                    out += struct.pack(">I", int(idx))
                i += int(L)
                continue

        if not allow_literals:
            raise ValueError("literal_disallowed")

        # Accumulate a literal run until the next match point, to keep item count low.
        j = i + 1
        while j < len(text) and _match_len_at(j) == 0 and (j - i) < 4096:
            j += 1
        lit = text[i:j]
        lit_b = lit.encode("utf-8")
        if len(lit_b) > MAX_LITERAL_BYTES:
            raise ValueError("literal_too_large")
        allow_literals_used = 1
        out += b"\x02" + struct.pack(">H", len(lit_b)) + lit_b
        i = j

    if allow_literals_used:
        out[8 + 1] = 0x01

    if len(out) > MAX_BLOB_BYTES:
        raise ValueError("blob_too_large")
    return bytes(out)


def decode_text(blob: bytes, vocab: Vocab, *, allow_literals: bool = True) -> Tuple[bool, str, str]:
    """
    Returns (ok, reason, text).

    Reasons:
    - wrong_vocab: vocab_id mismatch
    - corrupt: malformed stream / bad lengths
    - bad_magic: not an IDREVOC1 blob
    - bad_utf8: literal segment not valid UTF-8
    - literal_disallowed: literal segment present but allow_literals=False
    - text_too_large / blob_too_large: defensive cap trips
    """
    if not isinstance(blob, (bytes, bytearray)):
        return False, "bad_type", ""
    if not isinstance(vocab, Vocab):
        return False, "bad_vocab", ""
    bb = bytes(blob)
    if len(bb) > MAX_BLOB_BYTES:
        return False, "blob_too_large", ""
    if len(bb) < 8 + 1 + 1 + 2:
        return False, "too_short", ""
    if bb[:8] != MAGIC8:
        return False, "bad_magic", ""

    off = 8
    index_width = int(bb[off])
    off += 1
    _flags = int(bb[off])
    off += 1
    if index_width not in (2, 4):
        return False, "bad_index_width", ""

    vid_len = struct.unpack(">H", bb[off : off + 2])[0]
    off += 2
    if int(vid_len) <= 0 or int(vid_len) > int(MAX_VOCAB_ID_LEN):
        return False, "bad_vocab_id_len", ""
    if off + int(vid_len) > len(bb):
        return False, "corrupt", ""
    vid = bb[off : off + int(vid_len)]
    off += int(vid_len)
    if bytes(vid) != bytes(vocab.vocab_id):
        return False, "wrong_vocab", ""

    out_parts: List[str] = []
    out_bytes = 0

    while off < len(bb):
        kind = int(bb[off])
        off += 1
        if kind == 0x01:
            need = index_width
            if off + need > len(bb):
                return False, "corrupt", ""
            if index_width == 2:
                idx = struct.unpack(">H", bb[off : off + 2])[0]
            else:
                idx = struct.unpack(">I", bb[off : off + 4])[0]
            off += need
            if int(idx) >= len(vocab.tokens):
                return False, "token_oob", ""
            s = vocab.tokens[int(idx)]
            out_parts.append(s)
            out_bytes += len(s.encode("utf-8"))
        elif kind == 0x02:
            if not allow_literals:
                return False, "literal_disallowed", ""
            if off + 2 > len(bb):
                return False, "corrupt", ""
            n = struct.unpack(">H", bb[off : off + 2])[0]
            off += 2
            if off + int(n) > len(bb):
                return False, "corrupt", ""
            raw = bb[off : off + int(n)]
            off += int(n)
            try:
                s = raw.decode("utf-8", errors="strict")
            except Exception:
                return False, "bad_utf8", ""
            out_parts.append(s)
            out_bytes += len(raw)
        else:
            return False, "corrupt", ""

        if out_bytes > MAX_TEXT_BYTES:
            return False, "text_too_large", ""

    return True, "ok", "".join(out_parts)
