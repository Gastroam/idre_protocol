"""Minimal WAV IO (PCM16) for offline IDRE transports.

No scipy dependency; uses Python stdlib `wave`.
"""

from __future__ import annotations

import wave
from typing import Tuple

import numpy as np


def write_wav_pcm16(path: str, sr: int, x: np.ndarray) -> None:
    """Write mono PCM16 WAV from float waveform in [-1, 1]."""
    sr = int(sr)
    x = np.asarray(x, dtype=np.float32).reshape(-1)
    x = np.clip(x, -1.0, 1.0)
    pcm = (x * 32767.0).round().astype(np.int16)

    with wave.open(path, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)  # int16
        wf.setframerate(sr)
        wf.writeframes(pcm.tobytes())


def read_wav_pcm16(path: str) -> Tuple[int, np.ndarray]:
    """Read mono PCM WAV and return (sr, float32 waveform in [-1, 1])."""
    with wave.open(path, "rb") as wf:
        n_ch = int(wf.getnchannels())
        sw = int(wf.getsampwidth())
        sr = int(wf.getframerate())
        n = int(wf.getnframes())
        raw = wf.readframes(n)

    if sw != 2:
        raise ValueError(f"Only PCM16 supported (sampwidth=2), got {sw}.")

    pcm = np.frombuffer(raw, dtype=np.int16)
    if n_ch == 1:
        x = pcm.astype(np.float32) / 32767.0
    else:
        # Downmix to mono by simple channel mean.
        pcm = pcm.reshape(-1, n_ch)
        x = pcm.mean(axis=1).astype(np.float32) / 32767.0

    return sr, x.reshape(-1)

