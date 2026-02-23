from __future__ import annotations

from idre_clean.core.frozen_physics import compute_fingerprint_bits_frozen_v12
from idre_clean.core.offline_envelope import open_envelope, seal
from idre_clean.core.profile import compute_field_profile_id
from idre_clean.core.vocab_codec import decode_text as vocab_decode_text, encode_text as vocab_encode_text, load_vocab

def _default_profile() -> dict:
    return {
        "proto": "HIVE-P2P/1.2",
        "backend": "frozen",
        "freeze_field": True,
        "embedding_dim": 64,
        "planes": 4,
        "tau_frac": 0.55,
        "n_angles": 72,
        "scan_resolution": 50,
        "threshold": 0.5,
        "anchor_weight": 80.0,
    }

def test_offline_envelope_roundtrip_and_tamper() -> None:
    seed = 7245
    bits = compute_fingerprint_bits_frozen_v12(seed=seed)
    profile_id = compute_field_profile_id(_default_profile())

    # Must exceed 255 bytes so offline payload framing can't accidentally use 1-byte lengths.
    pt = (b"hello offline sealed letter: " * 32)[:1024]
    blob = seal(bits=bits, plaintext=pt, field_profile_id=profile_id, expires_in_ms=60_000, compressed=False)

    ok, reason, hdr, out = open_envelope(bits=bits, blob=blob, expected_field_profile_id=profile_id)
    assert ok, reason
    assert hdr is not None
    assert out == pt

    tam = bytearray(blob)
    tam[-1] ^= 0x01
    ok2, reason2, _, _ = open_envelope(bits=bits, blob=bytes(tam), expected_field_profile_id=profile_id)
    assert not ok2
    assert reason2 in ("corrupt", "bad_payload_len", "bad_header_len")

def test_offline_envelope_expired() -> None:
    seed = 7245
    bits = compute_fingerprint_bits_frozen_v12(seed=seed)
    profile_id = compute_field_profile_id(_default_profile())

    created = 1_700_000_000_000
    blob = seal(
        bits=bits,
        plaintext=b"x",
        field_profile_id=profile_id,
        created_at_ms=created,
        expires_in_ms=1000,
        compressed=False,
    )

    ok, reason, _, _ = open_envelope(
        bits=bits,
        blob=blob,
        expected_field_profile_id=profile_id,
        now_ms=created + 5000,
        enforce_time=True,
    )
    assert not ok
    assert reason == "expired"

def test_offline_envelope_with_vocab_codec_roundtrip(tmp_path) -> None:
    seed = 7245
    bits = compute_fingerprint_bits_frozen_v12(seed=seed)
    profile_id = compute_field_profile_id(_default_profile())

    # Tiny positional vocab. The codec must preserve exact string including whitespace.
    tokens = ["Hello", " ", "world", "!", "\n"]
    vocab_path = tmp_path / "vocab.json"
    vocab_path.write_text(__import__("json").dumps(tokens), encoding="utf-8")
    vocab = load_vocab(str(vocab_path))

    s = "Hello world!\nHello world!"
    pt = vocab_encode_text(s, vocab, allow_literals=True)
    blob = seal(bits=bits, plaintext=pt, field_profile_id=profile_id, expires_in_ms=60_000, compressed=False)

    ok, reason, _hdr, out = open_envelope(bits=bits, blob=blob, expected_field_profile_id=profile_id)
    assert ok, reason
    assert out is not None
    ok2, reason2, text = vocab_decode_text(out, vocab, allow_literals=True)
    assert ok2, reason2
    assert text == s
