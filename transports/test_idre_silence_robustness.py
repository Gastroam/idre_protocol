#!/usr/bin/env python3
"""Robustness test for IDRE-Silence (zero-crossing prime-gap modulation).

Goal:
- Quantify how fragile the current scheme is under real-world transforms:
  resampling, noise, clipping, DC offset, filtering, jitter/dropouts, time shifts.

Notes:
- Uses numpy only (no scipy).
- Writes a JSON report under `transports/results/`.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Tuple

import numpy as np


HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REPO_ROOT)


def _now_ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _mkdirp(p: str) -> None:
    os.makedirs(p, exist_ok=True)


def _dominant_freq_hz(x: np.ndarray, sr: int) -> float:
    x = np.asarray(x, dtype=np.float64).reshape(-1)
    if x.size < 8:
        return 0.0
    # Hann window + rfft peak
    w = np.hanning(x.size)
    spec = np.abs(np.fft.rfft(x * w))
    freqs = np.fft.rfftfreq(x.size, d=1.0 / float(sr))
    idx = int(np.argmax(spec))
    return float(freqs[idx])


def _snr_db(signal: np.ndarray, noisy: np.ndarray) -> float:
    s = np.asarray(signal, dtype=np.float64).reshape(-1)
    n = np.asarray(noisy, dtype=np.float64).reshape(-1) - s
    ps = float(np.mean(s * s)) + 1e-12
    pn = float(np.mean(n * n)) + 1e-12
    return 10.0 * float(np.log10(ps / pn))


def _quantize_int16(x: np.ndarray) -> np.ndarray:
    x = np.asarray(x, dtype=np.float64)
    x = np.clip(x, -1.0, 1.0)
    q = (x * 32767.0).round().astype(np.int16)
    return (q.astype(np.float64) / 32767.0).astype(np.float32)


def _add_noise(x: np.ndarray, sigma: float, rng: np.random.Generator) -> np.ndarray:
    x = np.asarray(x, dtype=np.float64)
    return (x + rng.normal(0.0, float(sigma), size=x.shape)).astype(np.float32)


def _dc_offset(x: np.ndarray, offset: float) -> np.ndarray:
    return (np.asarray(x, dtype=np.float64) + float(offset)).astype(np.float32)


def _clip(x: np.ndarray, limit: float) -> np.ndarray:
    lim = float(limit)
    return np.clip(np.asarray(x, dtype=np.float64), -lim, lim).astype(np.float32)


def _gain(x: np.ndarray, g: float) -> np.ndarray:
    return (np.asarray(x, dtype=np.float64) * float(g)).astype(np.float32)


def _prepend_silence(x: np.ndarray, sr: int, seconds: float) -> np.ndarray:
    n = max(0, int(float(seconds) * int(sr)))
    pad = np.zeros(n, dtype=np.float32)
    return np.concatenate([pad, np.asarray(x, dtype=np.float32)])


def _resample_linear(x: np.ndarray, sr_in: int, sr_out: int) -> np.ndarray:
    """Very simple linear resample (good enough to simulate pipeline damage)."""
    x = np.asarray(x, dtype=np.float64).reshape(-1)
    if x.size < 2 or sr_in <= 0 or sr_out <= 0:
        return np.asarray(x, dtype=np.float32)
    ratio = float(sr_out) / float(sr_in)
    n_out = max(2, int(np.floor(x.size * ratio)))
    t_in = np.linspace(0.0, 1.0, x.size, endpoint=False)
    t_out = np.linspace(0.0, 1.0, n_out, endpoint=False)
    y = np.interp(t_out, t_in, x)
    return y.astype(np.float32)


def _lowpass_fft(x: np.ndarray, sr: int, cutoff_hz: float) -> np.ndarray:
    x = np.asarray(x, dtype=np.float64).reshape(-1)
    if x.size < 8:
        return x.astype(np.float32)
    spec = np.fft.rfft(x)
    freqs = np.fft.rfftfreq(x.size, d=1.0 / float(sr))
    spec[freqs > float(cutoff_hz)] = 0
    y = np.fft.irfft(spec, n=x.size)
    return y.astype(np.float32)


def _highpass_fft(x: np.ndarray, sr: int, cutoff_hz: float) -> np.ndarray:
    x = np.asarray(x, dtype=np.float64).reshape(-1)
    if x.size < 8:
        return x.astype(np.float32)
    spec = np.fft.rfft(x)
    freqs = np.fft.rfftfreq(x.size, d=1.0 / float(sr))
    spec[freqs < float(cutoff_hz)] = 0
    y = np.fft.irfft(spec, n=x.size)
    return y.astype(np.float32)


def _dropout(x: np.ndarray, drop_prob: float, rng: np.random.Generator) -> np.ndarray:
    x = np.asarray(x, dtype=np.float64).reshape(-1)
    mask = rng.random(x.size) >= float(drop_prob)
    y = x * mask.astype(np.float64)
    return y.astype(np.float32)


def _time_jitter(x: np.ndarray, jitter_prob: float, rng: np.random.Generator) -> np.ndarray:
    """Randomly duplicate or remove samples (simulates clock jitter)."""
    x = np.asarray(x, dtype=np.float32).reshape(-1)
    out: List[float] = []
    for s in x.tolist():
        r = float(rng.random())
        if r < float(jitter_prob) / 2.0:
            # drop sample
            continue
        out.append(float(s))
        if r > 1.0 - float(jitter_prob) / 2.0:
            # duplicate sample
            out.append(float(s))
    if not out:
        return np.zeros(1, dtype=np.float32)
    return np.asarray(out, dtype=np.float32)


@dataclass
class Case:
    name: str
    fn: Callable[[np.ndarray], np.ndarray]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sr", type=int, default=44100)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--message", type=str, default="OFFLINE_IDRE_TEST_VECTOR_0001")
    ap.add_argument("--trials", type=int, default=20)
    ap.add_argument("--fec-repeat", type=int, default=1)
    args = ap.parse_args()

    # Local import from folder layout
    from idre_clean.transports.idre_silence import IDRESilenceProtocol

    sr = int(args.sr)
    rng = np.random.default_rng(int(args.seed))
    codec = IDRESilenceProtocol(sample_rate=sr, fec_repeat=int(args.fec_repeat))

    base = codec.encode(args.message)
    base_q = _quantize_int16(base)
    base_freq = _dominant_freq_hz(base[: min(len(base), sr)], sr)

    report: Dict[str, Any] = {
        "ts": _now_ts(),
        "sr": sr,
        "seed": int(args.seed),
        "message": args.message,
        "message_len": len(args.message),
        "fec_repeat": int(args.fec_repeat),
        "base": {
            "samples": int(len(base)),
            "dominant_freq_hz_first_1s": base_freq,
            "gaps": {"0": int(codec.GAP_0), "1": int(codec.GAP_1), "null": int(codec.GAP_NULL)},
        },
        "cases": [],
    }

    cases: List[Case] = []
    cases.append(Case("clean_float32", lambda x: np.asarray(x, dtype=np.float32)))
    cases.append(Case("wav_int16_roundtrip", lambda x: _quantize_int16(x)))

    # Noise sweeps
    for sigma in (0.001, 0.003, 0.01, 0.03, 0.1):
        cases.append(Case(f"noise_sigma_{sigma}", lambda x, s=sigma: _add_noise(x, s, rng)))

    # Resampling pipelines
    cases.append(Case("resample_44100_to_48000_to_44100", lambda x: _resample_linear(_resample_linear(x, sr, 48000), 48000, sr)))
    cases.append(Case("resample_44100_to_32000_to_44100", lambda x: _resample_linear(_resample_linear(x, sr, 32000), 32000, sr)))

    # Amplitude damage
    cases.append(Case("gain_x2_clip_0p6", lambda x: _clip(_gain(x, 2.0), 0.6)))
    cases.append(Case("gain_x0p2", lambda x: _gain(x, 0.2)))
    cases.append(Case("dc_offset_0p2", lambda x: _dc_offset(x, 0.2)))

    # Filtering
    cases.append(Case("lowpass_150hz", lambda x: _lowpass_fft(x, sr, 150.0)))
    cases.append(Case("highpass_80hz", lambda x: _highpass_fft(x, sr, 80.0)))

    # Timing issues
    cases.append(Case("prepend_0p25s_silence", lambda x: _prepend_silence(x, sr, 0.25)))
    cases.append(Case("dropout_1pct", lambda x: _dropout(x, 0.01, rng)))
    cases.append(Case("jitter_0p5pct", lambda x: _time_jitter(x, 0.005, rng)))

    for case in cases:
        successes = 0
        decoded_samples: List[str] = []
        snrs: List[float] = []
        freqs: List[float] = []
        lengths: List[int] = []

        for _t in range(int(args.trials)):
            x = case.fn(base_q)
            decoded = codec.decode(x)
            decoded_samples.append(decoded)
            successes += int(decoded == args.message)
            lengths.append(len(decoded))

            # quality signals (best-effort)
            try:
                snrs.append(_snr_db(base_q[: min(len(base_q), len(x))], x[: min(len(base_q), len(x))]))
            except Exception:
                pass
            try:
                freqs.append(_dominant_freq_hz(x[: min(len(x), sr)], sr))
            except Exception:
                pass

        report["cases"].append(
            {
                "name": case.name,
                "trials": int(args.trials),
                "successes": int(successes),
                "success_rate": float(successes) / float(args.trials),
                "decoded_len_stats": {
                    "min": int(min(lengths) if lengths else 0),
                    "max": int(max(lengths) if lengths else 0),
                    "mean": float(np.mean(np.asarray(lengths, dtype=np.float64)) if lengths else 0.0),
                },
                "snr_db": {
                    "min": float(min(snrs) if snrs else 0.0),
                    "mean": float(np.mean(np.asarray(snrs, dtype=np.float64)) if snrs else 0.0),
                },
                "dominant_freq_hz_first_1s": {
                    "min": float(min(freqs) if freqs else 0.0),
                    "mean": float(np.mean(np.asarray(freqs, dtype=np.float64)) if freqs else 0.0),
                },
                "example_decoded": decoded_samples[0] if decoded_samples else "",
            }
        )

    out_dir = os.path.join(HERE, "results")
    _mkdirp(out_dir)
    out_path = os.path.join(out_dir, f"idre_silence_robustness_{int(time.time())}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("WROTE", out_path)
    for c in report["cases"]:
        print(f"{c['name']:<32} success_rate={c['success_rate']:.2f} decoded_len_mean={c['decoded_len_stats']['mean']:.1f}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
