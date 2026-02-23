#!/usr/bin/env python3
"""Extract a positional vocab.json (JSON array of strings) from a HuggingFace tokenizers tokenizer.json.

This repo's vocab codec expects:
  vocab.json = ["<pad>", "<eos>", ...]  # positional list, index is the token id

This script supports BPE tokenizers where tokenizer.json contains:
  {"model": {"type": "BPE", "vocab": {token: id, ...}}}

It writes ASCII-only JSON (`ensure_ascii=True`) so the file is portable.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import sys

from idre_clean.core.vocab_store import write_vocab_bin

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", required=True, help="Path to tokenizer.json")
    ap.add_argument("--out", dest="out_path", required=True, help="Path to write vocab.json")
    ap.add_argument("--max-tokens", type=int, default=0, help="Optional cap for debugging (0 = no cap)")
    ap.add_argument(
        "--sp-to-space",
        action="store_true",
        help="Replace SentencePiece space marker (U+2581) with real space to produce human text tokens.",
    )
    args = ap.parse_args()

    inp = Path(args.in_path)
    outp = Path(args.out_path)
    d = json.loads(inp.read_text(encoding="utf-8"))
    model = d.get("model", {})
    if not isinstance(model, dict):
        raise SystemExit("ERROR: tokenizer.json missing model dict")
    if str(model.get("type", "")).upper() != "BPE":
        raise SystemExit(f"ERROR: unsupported model type {model.get('type')!r} (expected BPE)")
    vocab = model.get("vocab")
    if not isinstance(vocab, dict):
        raise SystemExit("ERROR: tokenizer.json model.vocab missing/invalid")

    # Build id->token list.
    n = len(vocab)
    tokens = [None] * n  # type: ignore[list-item]
    for tok, tid in vocab.items():
        if not isinstance(tok, str):
            continue
        try:
            i = int(tid)
        except Exception:
            continue
        if i < 0 or i >= n:
            raise SystemExit(f"ERROR: token id out of range: {tok!r} -> {i}")
        if tokens[i] is not None:
            raise SystemExit(f"ERROR: duplicate token id {i} for {tok!r} and {tokens[i]!r}")
        tokens[i] = tok

    missing = [i for i, t in enumerate(tokens) if t is None]
    if missing:
        raise SystemExit(f"ERROR: missing token ids (example): {missing[:10]}")

    if int(args.max_tokens) > 0:
        tokens = tokens[: int(args.max_tokens)]

    outp.parent.mkdir(parents=True, exist_ok=True)
    if bool(args.sp_to_space):
        sp = chr(0x2581)
        tokens = [t.replace(sp, " ") for t in tokens]

    if outp.suffix.lower() == ".bin":
        from hashlib import sha256

        # Same scheme as codec: sha256(json.dumps(tokens, ensure_ascii=True,separators=(',',':')) bytes)[:16],
        # computed incrementally to avoid building a huge JSON blob.
        h = sha256()
        h.update(b"[")
        first = True
        for t in tokens:
            if not first:
                h.update(b",")
            first = False
            h.update(json.dumps(t, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))
        h.update(b"]")
        vid = h.digest()[:16]
        write_vocab_bin(tokens=tokens, vocab_id=vid, out_path=str(outp))
        print("WROTE", str(outp), "tokens", len(tokens))
        return 0

    outp.write_text(json.dumps(tokens, ensure_ascii=True, separators=(",", ":")), encoding="utf-8")
    print("WROTE", str(outp), "tokens", len(tokens))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
