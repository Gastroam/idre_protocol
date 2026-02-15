#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
import time
import zlib

# Allow running as a script from within the standalone package folder:
# when repo root is `F:\idre_clean`, the parent (`F:\`) must be on sys.path
# for `import idre_clean.*` to work.
from pathlib import Path

_REPO_PARENT = str(Path(__file__).resolve().parents[2])
if _REPO_PARENT not in sys.path:
    sys.path.insert(0, _REPO_PARENT)

from idre_clean.core.frozen_physics import compute_fingerprint_bits_frozen_v12
from idre_clean.core.offline_envelope import open_envelope, seal
from idre_clean.core.profile import compute_field_profile_id
from idre_clean.core.vocab_codec import decode_text as vocab_decode_text, encode_text as vocab_encode_text, load_vocab
from idre_clean.transports.idre_silence import IDRESilenceProtocol
from idre_clean.transports.wav_io import read_wav_pcm16, write_wav_pcm16


def _profile_dict(args: argparse.Namespace) -> dict:
    return {
        "proto": "HIVE-P2P/1.2",
        "backend": str(args.backend),
        "freeze_field": bool(args.freeze_field),
        "embedding_dim": int(args.embedding_dim),
        "planes": int(args.planes),
        "tau_frac": float(args.tau_frac),
        "n_angles": int(args.n_angles),
        "scan_resolution": int(args.scan_resolution),
        "threshold": float(args.threshold),
        "anchor_weight": float(args.anchor_weight),
    }


def _codec(args: argparse.Namespace) -> IDRESilenceProtocol:
    # Mirror idre_silence_cli defaults (stealth_100hz).
    return IDRESilenceProtocol(
        sample_rate=44100,
        gap_0=431,
        gap_1=467,
        gap_null=449,
        symbol_cycles=3,
        preamble_cycles=12,
        tol_samples=6.0,
        hysteresis=0.01,
        smooth_cutoff_hz=300.0,
        min_crossing_sep=200.0,
        post_crossing_hold=32,
        fec_repeat=int(args.fec_repeat),
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--backend", default="frozen", choices=["frozen"], help="Only frozen backend supported here.")
    common.add_argument("--freeze-field", action="store_true", default=True)
    common.add_argument("--seed", type=int, required=True)
    common.add_argument("--anchor-weight", type=float, default=80.0)
    common.add_argument("--embedding-dim", type=int, default=64)
    common.add_argument("--planes", type=int, default=4)
    common.add_argument("--tau-frac", type=float, default=0.55)
    common.add_argument("--n-angles", type=int, default=72)
    common.add_argument("--scan-resolution", type=int, default=50)
    common.add_argument("--threshold", type=float, default=0.5)
    common.add_argument("--fec-repeat", type=int, default=3)

    enc = sub.add_parser("encode-letter", parents=[common])
    enc.add_argument("--in-file", required=True)
    enc.add_argument("--out-wav", required=True)
    enc.add_argument("--expires-in-ms", type=int, default=7 * 24 * 3600 * 1000)
    enc.add_argument("--compress", action="store_true")
    enc.add_argument("--pad-bytes", type=int, default=0)
    enc.add_argument("--src-hint", default="")
    enc.add_argument("--dst-hint", default="")
    enc.add_argument("--purpose", default="letter")

    dec = sub.add_parser("decode-letter", parents=[common])
    dec.add_argument("--in-wav", required=True)
    dec.add_argument("--out-file", required=True)
    dec.add_argument("--print-plaintext", action="store_true")

    vcommon = argparse.ArgumentParser(add_help=False)
    vcommon.add_argument("--vocab-file", required=True, help="Vocab file (.json or .bin).")
    vcommon.add_argument("--vocab-allow-literals", action=argparse.BooleanOptionalAction, default=True)

    venc = sub.add_parser("encode-text-vocab", parents=[common, vcommon])
    venc.add_argument("--in-file", required=True, help="UTF-8 text file")
    venc.add_argument("--out-wav", required=True)
    venc.add_argument("--expires-in-ms", type=int, default=7 * 24 * 3600 * 1000)
    venc.add_argument("--compress", action="store_true")
    venc.add_argument("--pad-bytes", type=int, default=0)
    venc.add_argument("--src-hint", default="")
    venc.add_argument("--dst-hint", default="")
    venc.add_argument("--purpose", default="letter")

    vdec = sub.add_parser("decode-text-vocab", parents=[common, vcommon])
    vdec.add_argument("--in-wav", required=True)
    vdec.add_argument("--out-file", required=True)
    vdec.add_argument("--print-plaintext", action="store_true")

    args = ap.parse_args()

    profile = _profile_dict(args)
    field_profile_id = compute_field_profile_id(profile)
    bits = compute_fingerprint_bits_frozen_v12(
        seed=int(args.seed),
        embedding_dim=int(args.embedding_dim),
        planes=int(args.planes),
        tau_frac=float(args.tau_frac),
        n_angles=int(args.n_angles),
        scan_resolution=int(args.scan_resolution),
        threshold=float(args.threshold),
        anchor_weight=float(args.anchor_weight),
    )

    codec = _codec(args)

    if args.cmd == "encode-letter":
        raw = open(args.in_file, "rb").read()
        data = raw
        compressed = False
        if args.compress:
            data = zlib.compress(raw, level=9)
            compressed = True

        blob = seal(
            bits=bits,
            plaintext=data,
            field_profile_id=field_profile_id,
            expires_in_ms=int(args.expires_in_ms),
            src_hint=str(args.src_hint),
            dst_hint=str(args.dst_hint),
            purpose=str(args.purpose),
            compressed=bool(compressed),
            pad_bytes=int(args.pad_bytes),
        )

        audio = codec.encode_bytes(blob, carrier_amplitude=0.5)
        os.makedirs(os.path.dirname(args.out_wav) or ".", exist_ok=True)
        write_wav_pcm16(args.out_wav, 44100, audio)
        print("WROTE", args.out_wav)
        print("field_profile_id", field_profile_id)
        print("bytes", len(blob), "expires_in_ms", int(args.expires_in_ms), "compressed", compressed)
        return 0

    if args.cmd == "decode-letter":
        sr, x = read_wav_pcm16(args.in_wav)
        if sr != 44100:
            # codec assumes 44.1k; decoder is fairly tolerant but we enforce for now.
            print("WARN: sample_rate", sr, "expected 44100; continuing")
        payload = codec.decode_bytes(x, expected_prefix=b"IDREOFF1")
        if payload is None:
            print("FAIL decode_bytes")
            return 2

        ok, reason, hdr, pt = open_envelope(bits=bits, blob=payload, expected_field_profile_id=field_profile_id)
        if not ok:
            print("FAIL open_envelope", reason)
            return 3

        assert hdr is not None and pt is not None
        out = pt
        if hdr.compressed:
            out = zlib.decompress(out)

        os.makedirs(os.path.dirname(args.out_file) or ".", exist_ok=True)
        open(args.out_file, "wb").write(out)
        print("WROTE", args.out_file)
        print("field_profile_id", field_profile_id)
        print("created_at_ms", hdr.created_at_ms, "expires_at_ms", hdr.expires_at_ms, "now_ms", int(time.time() * 1000.0))
        print("compressed", bool(hdr.compressed), "bytes", len(out))
        if args.print_plaintext:
            try:
                print(out.decode("utf-8", errors="replace"))
            except Exception:
                print(out)
        return 0

    if args.cmd == "encode-text-vocab":
        vocab = load_vocab(str(args.vocab_file))
        raw_text = open(args.in_file, "rb").read()
        try:
            text = raw_text.decode("utf-8", errors="strict")
        except Exception:
            print("FAIL bad_utf8")
            return 2

        # Common Windows/PowerShell artifacts:
        # - UTF-8 BOM becomes a leading U+FEFF.
        # - Line endings may be CRLF, leaving '\r' in the decoded text.
        # Normalize so strict vocab mode doesn't fail on invisible/OS-specific chars.
        if text.startswith("\ufeff"):
            text = text.lstrip("\ufeff")
        if "\r" in text:
            text = text.replace("\r\n", "\n").replace("\r", "\n")

        blob_pt = vocab_encode_text(text, vocab, allow_literals=bool(args.vocab_allow_literals))
        data = blob_pt
        compressed = False
        if args.compress:
            data = zlib.compress(blob_pt, level=9)
            compressed = True

        blob = seal(
            bits=bits,
            plaintext=data,
            field_profile_id=field_profile_id,
            expires_in_ms=int(args.expires_in_ms),
            src_hint=str(args.src_hint),
            dst_hint=str(args.dst_hint),
            purpose=str(args.purpose),
            compressed=bool(compressed),
            pad_bytes=int(args.pad_bytes),
        )

        audio = codec.encode_bytes(blob, carrier_amplitude=0.5)
        os.makedirs(os.path.dirname(args.out_wav) or ".", exist_ok=True)
        write_wav_pcm16(args.out_wav, 44100, audio)
        print("WROTE", args.out_wav)
        print("field_profile_id", field_profile_id)
        print("bytes", len(blob), "expires_in_ms", int(args.expires_in_ms), "compressed", compressed)
        return 0

    if args.cmd == "decode-text-vocab":
        vocab = load_vocab(str(args.vocab_file))
        sr, x = read_wav_pcm16(args.in_wav)
        if sr != 44100:
            print("WARN: sample_rate", sr, "expected 44100; continuing")
        payload = codec.decode_bytes(x, expected_prefix=b"IDREOFF1")
        if payload is None:
            print("FAIL decode_bytes")
            return 2

        ok, reason, hdr, pt = open_envelope(bits=bits, blob=payload, expected_field_profile_id=field_profile_id)
        if not ok:
            print("FAIL open_envelope", reason)
            return 3

        assert hdr is not None and pt is not None
        out = pt
        if hdr.compressed:
            out = zlib.decompress(out)

        ok2, reason2, text = vocab_decode_text(out, vocab, allow_literals=bool(args.vocab_allow_literals))
        if not ok2:
            print("FAIL vocab_decode", reason2)
            return 4

        os.makedirs(os.path.dirname(args.out_file) or ".", exist_ok=True)
        open(args.out_file, "wb").write(text.encode("utf-8"))
        print("WROTE", args.out_file)
        print("field_profile_id", field_profile_id)
        print("created_at_ms", hdr.created_at_ms, "expires_at_ms", hdr.expires_at_ms, "now_ms", int(time.time() * 1000.0))
        print("compressed", bool(hdr.compressed), "chars", len(text))
        if args.print_plaintext:
            print(text)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
