"""IDRE v3 Strict Private Vocabulary Manifest & Pre-Mutation Validation (Task 3).

Wraps `core.vocab_codec` and `core.vocab_store` without altering v2 behavior:
- Recomputes canonical ordered-content digests for every format (`.bin`, `.jsonl`, `.json`).
- Rejects `.bin` files whose stored `vocab_id` disagrees with canonical tokens.
- Rejects malformed `.jsonl` lines or non-string entries (no silent skipping).
- Rejects duplicate-conflicting registry entries.
- Enforces strict encoding (`allow_literals=False`) and `max_plaintext_bytes`
  before any field, codec, sequence, or outbox mutation.
"""

from __future__ import annotations

import hmac
import json
from pathlib import Path
from typing import Dict, List, Tuple

from core.profile_v3 import compute_vocab_digest_v3
from core.vocab_codec import (
    MAX_TEXT_BYTES,
    Vocab,
    _compute_vocab_id,
    decode_text,
    encode_text,
)
from core.vocab_store import read_vocab_bin


class VocabManifestError(ValueError):
    """Raised when a vocabulary artifact or strict encoding violates v3 integrity rules."""


def _build_vocab_from_tokens(tokens: List[str]) -> Vocab:
    if not tokens:
        raise VocabManifestError("vocabulary token list must not be empty")
    vocab_id = _compute_vocab_id(tokens)
    token_to_index: Dict[str, int] = {}
    for i, t in enumerate(tokens):
        if not isinstance(t, str) or not t:
            raise VocabManifestError("vocabulary tokens must be non-empty strings")
        if t not in token_to_index:
            token_to_index[t] = int(i)
    lens_by_first_char: Dict[str, List[int]] = {}
    for t in token_to_index:
        c0 = t[0]
        lens_by_first_char.setdefault(c0, []).append(len(t))
    for c, lens in list(lens_by_first_char.items()):
        lens_by_first_char[c] = sorted(set(int(x) for x in lens), reverse=True)
    return Vocab(
        tokens=list(tokens),
        token_to_index=token_to_index,
        vocab_id=vocab_id,
        lens_by_first_char=lens_by_first_char,
    )


def load_vocab_strict_v3(
    path: str,
    *,
    expected_vocab_digest: bytes,
    policy: str = "strict_vocab_v3",
) -> Vocab:
    """Load a vocabulary file strictly and verify its digest against trusted provisioning."""
    if not isinstance(expected_vocab_digest, (bytes, bytearray)) or len(expected_vocab_digest) != 32:
        raise VocabManifestError("expected_vocab_digest must be 32 bytes")

    p = Path(path)
    if not p.is_file():
        raise VocabManifestError(f"vocab file not found: {path}")

    suffix = p.suffix.lower()
    if suffix == ".bin":
        try:
            vb = read_vocab_bin(str(p))
        except Exception as exc:
            raise VocabManifestError(f"corrupt_vocab_bin: {exc}") from exc
        recomputed_id = _compute_vocab_id(list(vb.tokens))
        if not hmac.compare_digest(bytes(vb.vocab_id), recomputed_id):
            raise VocabManifestError("bin_vocab_id_mismatch_with_tokens")
        tokens = list(vb.tokens)
    elif suffix == ".jsonl":
        tokens = []
        raw_text = p.read_text(encoding="utf-8")
        for line_no, line in enumerate(raw_text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                val = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise VocabManifestError(f"malformed_jsonl_line_{line_no}") from exc
            if not isinstance(val, str):
                raise VocabManifestError(f"non_string_jsonl_line_{line_no}")
            tokens.append(val)
    elif suffix == ".json":
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            raise VocabManifestError("malformed_vocab_json") from exc
        if not isinstance(data, list) or not all(isinstance(x, str) for x in data):
            raise VocabManifestError("bad_vocab_json_schema")
        tokens = list(data)
    else:
        raise VocabManifestError(f"unsupported_vocab_format: {suffix}")

    vocab = _build_vocab_from_tokens(tokens)
    actual_digest = compute_vocab_digest_v3(vocab, policy=policy)
    if not hmac.compare_digest(actual_digest, bytes(expected_vocab_digest)):
        raise VocabManifestError("vocab_digest_mismatch_against_provisioning")
    return vocab


def load_vocab_registry_strict_v3(
    entries: List[Tuple[str, bytes]],
    *,
    policy: str = "strict_vocab_v3",
) -> Dict[bytes, Vocab]:
    """Load one or more `(path, expected_vocab_digest)` entries strictly.

    Rejects duplicate or conflicting `vocab_id` entries.
    """
    if not entries:
        raise VocabManifestError("registry entries must not be empty")
    registry: Dict[bytes, Vocab] = {}
    for path, expected_digest in entries:
        v = load_vocab_strict_v3(path, expected_vocab_digest=expected_digest, policy=policy)
        if v.vocab_id in registry:
            existing = registry[v.vocab_id]
            if existing.tokens != v.tokens:
                raise VocabManifestError("conflicting_duplicate_vocab_id_in_registry")
            raise VocabManifestError("duplicate_vocab_entry_in_registry")
        registry[v.vocab_id] = v
    return registry


def encode_strict_v3(text: str, vocab: Vocab, *, max_plaintext_bytes: int) -> bytes:
    """Strictly encode text without literal fallback and enforce capacity before mutation."""
    if not isinstance(text, str):
        raise VocabManifestError("text must be str")
    if max_plaintext_bytes <= 0:
        raise VocabManifestError("max_plaintext_bytes must be positive")
    if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
        raise VocabManifestError(
            f"text_too_large: {len(text.encode('utf-8'))} > {MAX_TEXT_BYTES}"
        )
    try:
        blob = encode_text(text, vocab, allow_literals=False)
    except ValueError as exc:
        raise VocabManifestError(f"strict_vocab_encode_failed: {exc}") from exc
    if len(blob) > max_plaintext_bytes:
        raise VocabManifestError(
            f"encoded_vocab_blob_oversize: {len(blob)} > {max_plaintext_bytes}"
        )
    return blob


def decode_strict_v3(blob: bytes, vocab: Vocab, *, max_plaintext_bytes: int) -> str:
    """Strictly decode a vocabulary blob without literal fallback."""
    if not isinstance(blob, (bytes, bytearray)):
        raise VocabManifestError("blob must be bytes")
    if len(blob) > max_plaintext_bytes:
        raise VocabManifestError(
            f"vocab_blob_oversize: {len(blob)} > {max_plaintext_bytes}"
        )
    ok, reason, text = decode_text(bytes(blob), vocab, allow_literals=False)
    if not ok:
        raise VocabManifestError(f"strict_vocab_decode_failed: {reason}")
    return text
