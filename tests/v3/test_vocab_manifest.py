"""Tests for Task 3: Strict private vocabulary manifest validation and pre-mutation checks."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.profile_v3 import compute_vocab_digest_v3
from core.vocab_codec import _compute_vocab_id, load_vocab
from core.vocab_store import write_vocab_bin
from core.vocab_v3 import (
    VocabManifestError,
    decode_strict_v3,
    encode_strict_v3,
    load_vocab_registry_strict_v3,
    load_vocab_strict_v3,
)


TOKENS = ["red", "blue", "green", " "]


def _make_json_vocab(path: Path, tokens=TOKENS):
    path.write_text(json.dumps(tokens), encoding="utf-8")
    v = load_vocab(str(path))
    return v, compute_vocab_digest_v3(v)


def test_valid_json_jsonl_and_bin_load_with_matching_digest(tmp_path: Path):
    jp = tmp_path / "vocab.json"
    v_ref, expected_digest = _make_json_vocab(jp)

    # JSON
    v_json = load_vocab_strict_v3(str(jp), expected_vocab_digest=expected_digest)
    assert v_json.tokens == TOKENS

    # JSONL
    jlp = tmp_path / "vocab.jsonl"
    jlp.write_text("\n".join(json.dumps(t) for t in TOKENS) + "\n", encoding="utf-8")
    v_jsonl = load_vocab_strict_v3(str(jlp), expected_vocab_digest=expected_digest)
    assert v_jsonl.tokens == TOKENS

    # BIN with valid matching vocab_id
    bp = tmp_path / "vocab.bin"
    write_vocab_bin(tokens=TOKENS, vocab_id=_compute_vocab_id(TOKENS), out_path=str(bp))
    v_bin = load_vocab_strict_v3(str(bp), expected_vocab_digest=expected_digest)
    assert v_bin.tokens == TOKENS


def test_bin_stored_id_disagreeing_with_tokens_is_rejected(tmp_path: Path):
    jp = tmp_path / "vocab.json"
    _, expected_digest = _make_json_vocab(jp)

    bp = tmp_path / "tampered.bin"
    # Valid tokens, but forged stored vocab_id
    write_vocab_bin(tokens=TOKENS, vocab_id=b"\xde\xad\xbe\xef" * 4, out_path=str(bp))
    with pytest.raises(VocabManifestError, match="bin_vocab_id_mismatch_with_tokens"):
        load_vocab_strict_v3(str(bp), expected_vocab_digest=expected_digest)


def test_malformed_jsonl_and_non_string_entries_rejected(tmp_path: Path):
    jp = tmp_path / "vocab.json"
    _, expected_digest = _make_json_vocab(jp)

    bad_json = tmp_path / "bad.jsonl"
    bad_json.write_text('"red"\n{not valid json\n"blue"\n', encoding="utf-8")
    with pytest.raises(VocabManifestError, match="malformed_jsonl"):
        load_vocab_strict_v3(str(bad_json), expected_vocab_digest=expected_digest)

    non_str = tmp_path / "nonstr.jsonl"
    non_str.write_text('"red"\n123\n"blue"\n', encoding="utf-8")
    with pytest.raises(VocabManifestError, match="non_string_jsonl"):
        load_vocab_strict_v3(str(non_str), expected_vocab_digest=expected_digest)


def test_reordered_tokens_and_duplicate_registry_rejected(tmp_path: Path):
    p1 = tmp_path / "v1.json"
    _, expected_digest = _make_json_vocab(p1, TOKENS)

    p_reordered = tmp_path / "v_reordered.json"
    p_reordered.write_text(json.dumps(["blue", "red", "green", " "]), encoding="utf-8")
    with pytest.raises(VocabManifestError, match="vocab_digest_mismatch"):
        load_vocab_strict_v3(str(p_reordered), expected_vocab_digest=expected_digest)

    # Duplicate entry in strict registry rejected
    with pytest.raises(VocabManifestError, match="duplicate_vocab_entry"):
        load_vocab_registry_strict_v3([(str(p1), expected_digest), (str(p1), expected_digest)])


def test_out_of_vocabulary_and_oversize_fail_before_state_mutation(tmp_path: Path):
    jp = tmp_path / "vocab.json"
    v_ref, expected_digest = _make_json_vocab(jp)
    vocab = load_vocab_strict_v3(str(jp), expected_vocab_digest=expected_digest)

    blob = encode_strict_v3("red blue green", vocab, max_plaintext_bytes=4023)
    assert decode_strict_v3(blob, vocab, max_plaintext_bytes=4023) == "red blue green"

    # Out-of-vocabulary input rejected (strict mode, no literal fallback)
    with pytest.raises(VocabManifestError, match="literal_disallowed"):
        encode_strict_v3("red yellow", vocab, max_plaintext_bytes=4023)

    # Oversize blob rejected before any state mutation
    with pytest.raises(VocabManifestError, match="oversize"):
        encode_strict_v3("red " * 2000, vocab, max_plaintext_bytes=128)
