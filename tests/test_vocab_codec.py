from __future__ import annotations

import json

import pytest

from idre_clean.core.vocab_codec import Vocab, decode_text, encode_text, load_vocab


def test_vocab_codec_roundtrip_exact(tmp_path) -> None:
    vocab_path = tmp_path / "vocab.json"
    tokens = ["Hello", " ", "world", "!", "\n", "Report", ":", "\t"]
    vocab_path.write_text(json.dumps(tokens), encoding="utf-8")
    vocab = load_vocab(str(vocab_path))

    s = "Hello world!\nReport:\tHello world!"
    blob = encode_text(s, vocab, allow_literals=True)
    ok, reason, out = decode_text(blob, vocab, allow_literals=True)
    assert ok, reason
    assert out == s


def test_vocab_codec_vocab_mismatch(tmp_path) -> None:
    p1 = tmp_path / "v1.json"
    p2 = tmp_path / "v2.json"
    p1.write_text(json.dumps(["a", " "]), encoding="utf-8")
    p2.write_text(json.dumps(["a", " ", "b"]), encoding="utf-8")
    v1 = load_vocab(str(p1))
    v2 = load_vocab(str(p2))

    blob = encode_text("a a", v1, allow_literals=True)
    ok, reason, _ = decode_text(blob, v2, allow_literals=True)
    assert not ok
    assert reason == "wrong_vocab"


def test_vocab_codec_limits_and_malformed(tmp_path) -> None:
    vocab_path = tmp_path / "vocab.json"
    vocab_path.write_text(json.dumps(["x"]), encoding="utf-8")
    vocab = load_vocab(str(vocab_path))

    # literal disallowed
    with pytest.raises(ValueError):
        _ = encode_text("y", vocab, allow_literals=False)

    blob = encode_text("y", vocab, allow_literals=True)
    ok, reason, _ = decode_text(blob, vocab, allow_literals=False)
    assert not ok
    assert reason == "literal_disallowed"

    # malformed stream: truncate
    ok2, reason2, _ = decode_text(blob[:-3], vocab, allow_literals=True)
    assert not ok2
    assert reason2 in ("corrupt", "too_short")

