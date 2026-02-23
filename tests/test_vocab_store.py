from __future__ import annotations

from core.vocab_store import read_vocab_bin, write_vocab_bin

def test_vocab_bin_roundtrip(tmp_path) -> None:
    tokens = ["a", " ", "b", "\n", "the"]
    vocab_id = b"\x01" * 16
    out = tmp_path / "vocab.bin"
    write_vocab_bin(tokens=tokens, vocab_id=vocab_id, out_path=str(out))
    vb = read_vocab_bin(str(out))
    assert vb.tokens == tokens
    assert vb.vocab_id == vocab_id

