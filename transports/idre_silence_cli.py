#!/usr/bin/env python3
"""Encode/decode long messages over IDRE-Silence (offline audio transport).

This is transport-only: it carries bytes. You should feed it already-secured
IDRE wire frames if you need confidentiality/integrity beyond CRC/FEC.
"""

from __future__ import annotations

import argparse
import sys
import time
import zlib
from dataclasses import dataclass
from typing import Optional, Tuple

import numpy as np

# Allow running as a script without installing the package.
from pathlib import Path
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from idre_clean.transports.idre_silence import IDRESilenceProtocol
from idre_clean.transports.wav_io import read_wav_pcm16, write_wav_pcm16


MAGIC = b"IDRS1"  # 5 bytes
FLAG_COMPRESSED = 0x01


@dataclass(frozen=True)
class Profile:
    name: str
    sr: int
    gap0: int
    gap1: int
    gapn: int
    symbol_cycles: int
    preamble_cycles: int
    tol_samples: float
    hysteresis: float
    smooth_cutoff_hz: float
    min_crossing_sep: float
    post_crossing_hold: int


def _profiles() -> dict:
    # Defaults are tuned for the "stealth hum" mode (~100 Hz).
    # `fast_250hz` is a throughput option (more audible), using shorter cycles.
    return {
        "stealth_100hz": Profile(
            name="stealth_100hz",
            sr=44100,
            gap0=431,
            gap1=467,
            gapn=449,
            symbol_cycles=3,
            preamble_cycles=12,
            tol_samples=6.0,
            hysteresis=0.01,
            smooth_cutoff_hz=300.0,
            min_crossing_sep=200.0,
            post_crossing_hold=32,
        ),
        "fast_250hz": Profile(
            name="fast_250hz",
            sr=44100,
            # Around 250 Hz: 44100/173=254.9, /179=246.4, /191=230.9
            gap0=173,
            gap1=191,
            gapn=179,
            symbol_cycles=2,
            preamble_cycles=10,
            tol_samples=5.0,
            hysteresis=0.01,
            smooth_cutoff_hz=600.0,
            min_crossing_sep=70.0,
            post_crossing_hold=16,
        ),
    }


def _wrap_payload(raw: bytes, *, compress: bool) -> bytes:
    flags = 0
    data = raw
    if compress:
        data = zlib.compress(raw, level=9)
        flags |= FLAG_COMPRESSED
    if len(data) > 0xFFFFFFFF:
        raise ValueError("payload too large")
    return MAGIC + bytes([flags]) + len(raw).to_bytes(4, "big") + data


def _unwrap_payload(p: bytes) -> Tuple[bytes, bool]:
    if len(p) < 10 or p[:5] != MAGIC:
        return p, False
    flags = int(p[5])
    orig_len = int.from_bytes(p[6:10], "big")
    data = p[10:]
    if flags & FLAG_COMPRESSED:
        data = zlib.decompress(data)
    if orig_len != 0 and len(data) != orig_len:
        # best-effort; transport CRC already validated
        pass
    return data, True


def _estimate_seconds(
    *,
    n_payload_bytes: int,
    sr: int,
    approx_gap: float,
    symbol_cycles: int,
    preamble_cycles: int,
    fec_repeat: int,
) -> float:
    # IDRESilenceProtocol frames: 2 bytes len + 4 bytes crc + payload
    n_framed = 6 + int(n_payload_bytes)
    n_bits = n_framed * 8 * int(max(1, fec_repeat))
    n_symbols = (2 * int(preamble_cycles)) + n_bits
    n_cycles = n_symbols * int(max(1, symbol_cycles))
    n_samples = float(n_cycles) * float(approx_gap)
    return float(n_samples) / float(sr)


def _make_codec(p: Profile, *, fec_repeat: int) -> IDRESilenceProtocol:
    return IDRESilenceProtocol(
        sample_rate=int(p.sr),
        gap_0=int(p.gap0),
        gap_1=int(p.gap1),
        gap_null=int(p.gapn),
        symbol_cycles=int(p.symbol_cycles),
        preamble_cycles=int(p.preamble_cycles),
        tol_samples=float(p.tol_samples),
        hysteresis=float(p.hysteresis),
        smooth_cutoff_hz=float(p.smooth_cutoff_hz),
        min_crossing_sep=float(p.min_crossing_sep),
        post_crossing_hold=int(p.post_crossing_hold),
        fec_repeat=int(fec_repeat),
    )


def cmd_encode(args: argparse.Namespace) -> int:
    profs = _profiles()
    p = profs.get(args.profile)
    if p is None:
        raise SystemExit(f"unknown profile: {args.profile!r}. choices: {', '.join(sorted(profs))}")

    if args.in_file:
        raw = open(args.in_file, "rb").read()
    else:
        raw = (args.message or "").encode("utf-8")

    payload = _wrap_payload(raw, compress=bool(args.compress))
    codec = _make_codec(p, fec_repeat=int(args.fec_repeat))

    approx_gap = float(np.median([codec.GAP_0, codec.GAP_1, codec.GAP_NULL]))
    secs = _estimate_seconds(
        n_payload_bytes=len(payload),
        sr=int(codec.sr),
        approx_gap=approx_gap,
        symbol_cycles=int(codec.symbol_cycles),
        preamble_cycles=int(codec.preamble_cycles),
        fec_repeat=int(codec.fec_repeat),
    )

    out_wav = args.out_wav or f"idre_silence_{int(time.time())}.wav"
    print(f"[encode] profile={p.name} sr={codec.sr} fec_repeat={codec.fec_repeat} symbol_cycles={codec.symbol_cycles}")
    print(f"[encode] payload_bytes={len(raw)} wrapped_bytes={len(payload)} est_duration_s={secs:.1f} (~{secs/60.0:.1f} min)")

    audio = codec.encode_bytes(payload, carrier_amplitude=float(args.amplitude))
    write_wav_pcm16(out_wav, int(codec.sr), audio)
    print(f"[encode] wrote {out_wav}")

    if args.verify:
        sr2, x = read_wav_pcm16(out_wav)
        if sr2 != int(codec.sr):
            print(f"[verify] warning: wav sr={sr2} != codec sr={codec.sr}")
        dec = codec.decode_bytes(x)
        if dec is None:
            print("[verify] FAIL: decode_bytes returned None")
            return 2
        dec_raw, _ = _unwrap_payload(dec)
        ok = dec_raw == raw
        print(f"[verify] {'OK' if ok else 'FAIL'} decoded_bytes={len(dec_raw)}")
        return 0 if ok else 3

    return 0


def cmd_decode(args: argparse.Namespace) -> int:
    profs = _profiles()
    p = profs.get(args.profile)
    if p is None:
        raise SystemExit(f"unknown profile: {args.profile!r}. choices: {', '.join(sorted(profs))}")

    codec = _make_codec(p, fec_repeat=int(args.fec_repeat))
    sr, x = read_wav_pcm16(args.in_wav)
    if sr != int(codec.sr):
        print(f"[decode] warning: wav sr={sr} != codec sr={codec.sr}")

    payload = codec.decode_bytes(x)
    if payload is None:
        print("[decode] FAIL: decode_bytes returned None")
        return 2

    raw, had_hdr = _unwrap_payload(payload)
    if args.out_file:
        open(args.out_file, "wb").write(raw)
        print(f"[decode] wrote {args.out_file} bytes={len(raw)} header={had_hdr}")
    else:
        # Best effort: print as UTF-8.
        try:
            s = raw.decode("utf-8", errors="strict")
        except Exception:
            s = raw.decode("utf-8", errors="replace")
        print(s)
        print(f"[decode] bytes={len(raw)} header={had_hdr}", file=sys.stderr)

    return 0


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_enc = sub.add_parser("encode", help="encode message/file to wav")
    ap_enc.add_argument("--profile", type=str, default="stealth_100hz")
    ap_enc.add_argument("--fec-repeat", type=int, default=3)
    ap_enc.add_argument("--amplitude", type=float, default=0.5)
    ap_enc.add_argument("--compress", action="store_true")
    ap_enc.add_argument("--verify", action="store_true")
    ap_enc.add_argument("--message", type=str, default="")
    ap_enc.add_argument("--in-file", type=str, default="")
    ap_enc.add_argument("--out-wav", type=str, default="")
    ap_enc.set_defaults(fn=cmd_encode)

    ap_dec = sub.add_parser("decode", help="decode wav to message/file")
    ap_dec.add_argument("--profile", type=str, default="stealth_100hz")
    ap_dec.add_argument("--fec-repeat", type=int, default=3)
    ap_dec.add_argument("--in-wav", type=str, required=True)
    ap_dec.add_argument("--out-file", type=str, default="")
    ap_dec.set_defaults(fn=cmd_decode)

    args = ap.parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
