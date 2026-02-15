"""transports/idre_silence.py

IDRE-Silence (Transport Layer)

This is an offline/air-gap carrier for an already-secured payload (e.g., an IDRE packet).
It must be robust under mild noise and common audio pipeline damage.

Design changes vs legacy PoC:
- Fractional zero-crossing timing (linear interpolation) to reduce sample-quantization errors.
- Preamble-based sync (find a run of NULL symbols).
- Symbol repetition + majority vote (defaults keep throughput reasonable at ~100 Hz carrier).
- Optional CRC framing for bytes payloads.

Dependencies: numpy (only).
"""

from __future__ import annotations

import zlib
from typing import List, Optional

import numpy as np

class IDRESilenceProtocol:
    """
    Implements the IDRE-Silence Protocol.
    Encodes data into the geometry of zero-crossings using Prime Gaps.
    """
    
    # Prime Gaps for encoding (at 44.1kHz)
    # 43 samples ~= 1025 Hz (High pitch for carrier? No, these are half-cycles?)
    # Let's target a low drone ~60Hz. 
    # 44100 / 60 = 735 samples per cycle.
    # Primes near 735:
    # 733 (0), 739 (1), 743 (null)
    
    # Let's use simpler/shorter gaps for higher data rate if we want "Lo-Fi Hum"
    # ~100Hz = 441 samples.
    # Gap 0: 439 (Prime)
    # Gap 1: 443 (Prime)
    # Gap Null: 449 (Prime)
    
    # Default gaps are near 100 Hz at 44.1 kHz, but spaced enough to survive
    # mild timing damage (resampling/jitter/noise).
    #
    # Frequencies:
    # 44100/431=102.32, 44100/449=98.22, 44100/467=94.43
    #
    # Note: earlier PoC used much tighter gaps (439/443/449). Those are easier
    # to confuse once you add jitter or noise because the symbol spacing is only 4 samples.
    GAP_0 = 431
    GAP_1 = 467
    GAP_NULL = 449
    
    def __init__(
        self,
        sample_rate: int = 44100,
        gap_0: int = GAP_0,
        gap_1: int = GAP_1,
        gap_null: int = GAP_NULL,
        symbol_cycles: int = 3,
        preamble_cycles: int = 12,
        tol_samples: float = 6.0,
        hysteresis: float = 0.01,
        smooth_cutoff_hz: float = 300.0,
        min_crossing_sep: float = 200.0,
        post_crossing_hold: int = 32,
        fec_repeat: int = 1,
    ):
        self.sr = int(sample_rate)
        self.GAP_0 = int(gap_0)
        self.GAP_1 = int(gap_1)
        self.GAP_NULL = int(gap_null)
        self.symbol_cycles = int(symbol_cycles)
        self.preamble_cycles = int(preamble_cycles)
        self.tol_samples = float(tol_samples)
        self.hysteresis = float(hysteresis)
        self.smooth_cutoff_hz = float(smooth_cutoff_hz)
        self.min_crossing_sep = float(min_crossing_sep)
        self.post_crossing_hold = int(post_crossing_hold)
        self.fec_repeat = int(fec_repeat)

        if self.symbol_cycles < 1:
            raise ValueError("symbol_cycles must be >= 1")
        if self.preamble_cycles < 4:
            raise ValueError("preamble_cycles must be >= 4")
        if self.GAP_0 <= 0 or self.GAP_1 <= 0 or self.GAP_NULL <= 0:
            raise ValueError("gaps must be > 0")
        if self.fec_repeat < 1 or self.fec_repeat > 9:
            raise ValueError("fec_repeat must be in [1, 9]")

    def text_to_bits(self, text):
        """Convert string to list of bits"""
        bits = []
        for char in text:
            # 8-bit ASCII/UTF-8
            val = ord(char)
            for i in range(7, -1, -1):
                bits.append((val >> i) & 1)
        return bits

    def bits_to_text(self, bits):
        """Convert list of bits to string"""
        chars = []
        for i in range(0, len(bits), 8):
            byte_bits = bits[i:i+8]
            if len(byte_bits) < 8: break
            val = 0
            for bit in byte_bits:
                val = (val << 1) | bit
            chars.append(chr(val))
        return "".join(chars)

    def _bytes_to_bits(self, payload: bytes) -> List[int]:
        bits: List[int] = []
        for b in payload:
            for i in range(7, -1, -1):
                bits.append((b >> i) & 1)
        return bits

    def _bits_to_bytes(self, bits: List[int]) -> bytes:
        out = bytearray()
        for i in range(0, len(bits), 8):
            chunk = bits[i : i + 8]
            if len(chunk) < 8:
                break
            v = 0
            for bit in chunk:
                v = (v << 1) | (int(bit) & 1)
            out.append(v & 0xFF)
        return bytes(out)

    def _frame_bytes(self, payload: bytes) -> bytes:
        n = len(payload)
        if n > 65535:
            raise ValueError("payload too large")
        crc = zlib.crc32(payload) & 0xFFFFFFFF
        return n.to_bytes(2, "big") + crc.to_bytes(4, "big") + payload

    def _unframe_bytes(self, framed: bytes) -> Optional[bytes]:
        if len(framed) < 6:
            return None
        n = int.from_bytes(framed[0:2], "big")
        crc = int.from_bytes(framed[2:6], "big")
        data = framed[6 : 6 + n]
        if len(data) != n:
            return None
        if (zlib.crc32(data) & 0xFFFFFFFF) != crc:
            return None
        return data

    def _fec_encode_bits(self, bits: List[int]) -> List[int]:
        r = int(self.fec_repeat)
        if r <= 1:
            return [int(b) & 1 for b in bits]
        out: List[int] = []
        for b in bits:
            bb = int(b) & 1
            out.extend([bb] * r)
        return out

    def _fec_decode_bits(self, rx_bits: List[int]) -> List[int]:
        r = int(self.fec_repeat)
        if r <= 1:
            return [int(b) & 1 for b in rx_bits]
        out: List[int] = []
        n = (len(rx_bits) // r) * r
        for i in range(0, n, r):
            grp = rx_bits[i : i + r]
            ones = int(sum(int(b) & 1 for b in grp))
            out.append(1 if ones > (r // 2) else 0)
        return out

    def encode_bytes(self, payload: bytes, carrier_amplitude: float = 0.5) -> np.ndarray:
        """Encode arbitrary bytes into a near-100 Hz carrier."""
        framed = self._frame_bytes(payload)
        bits = self._fec_encode_bits(self._bytes_to_bits(framed))

        # Preamble/postamble: NULL cycles for sync and decode termination.
        pre = [None] * int(self.preamble_cycles)
        post = [None] * int(self.preamble_cycles)
        stream: List[Optional[int]] = pre + [int(b) for b in bits] + post

        audio_buffer = []
        for sym in stream:
            if sym == 0:
                cycle_len = self.GAP_0
            elif sym == 1:
                cycle_len = self.GAP_1
            else:
                cycle_len = self.GAP_NULL

            # Repeat cycles per symbol for robustness.
            for _ in range(int(self.symbol_cycles)):
                t = np.linspace(0.0, 2.0 * np.pi, int(cycle_len), endpoint=False)
                audio_buffer.append(np.sin(t) * float(carrier_amplitude))

        return np.concatenate(audio_buffer).astype(np.float32)

    def encode(self, text, carrier_amplitude=0.5):
        """Encode UTF-8 text as bytes transport."""
        return self.encode_bytes((text or "").encode("utf-8"), carrier_amplitude=float(carrier_amplitude))

    def _rising_zero_crossings(self, x: np.ndarray) -> np.ndarray:
        """Return fractional indices of rising zero-crossings.

        Uses a Schmitt-trigger style guard to avoid chatter under noise:
        - arm when signal goes below -hysteresis
        - trigger when it later exceeds +hysteresis

        Crossing time is estimated at 0 via linear interpolation near the trigger.
        """
        x = np.asarray(x, dtype=np.float64).reshape(-1)
        if x.size < 2:
            return np.zeros((0,), dtype=np.float64)

        # Light low-pass (EMA) to suppress high-frequency noise that creates extra crossings.
        fc = float(self.smooth_cutoff_hz)
        if fc > 0.0:
            dt = 1.0 / float(self.sr)
            rc = 1.0 / (2.0 * np.pi * fc)
            alpha = dt / (rc + dt)
            y = np.empty_like(x)
            y[0] = x[0]
            for i in range(1, x.size):
                y[i] = (alpha * x[i]) + ((1.0 - alpha) * y[i - 1])
            x = y

        h = float(self.hysteresis)
        hold = int(self.post_crossing_hold)
        min_sep = float(self.min_crossing_sep)

        idxs: List[float] = []
        armed = False
        last_idx = -1e18

        # Arm if we start already below -h.
        if x[0] <= -h:
            armed = True

        # State machine:
        # - arm after we have seen a sufficiently negative value (<= -h)
        # - accept the first rising 0-crossing (x[i-1] <= 0 < x[i]) after arming
        # - reject chatter by requiring that we reach +h shortly after crossing
        # - enforce a minimum separation between accepted crossings
        for i in range(1, x.size):
            if not armed:
                if x[i] <= -h:
                    armed = True
                continue

            if not (x[i - 1] <= 0.0 and x[i] > 0.0):
                continue

            # Minimum spacing filter (noise can create extra micro-crossings near 0).
            if float(i) - float(last_idx) < min_sep:
                continue

            # Hold filter: ensure this is not just a single-sample spike.
            j2 = min(x.size, i + max(1, hold))
            if float(np.max(x[i:j2])) < h:
                continue

            # Interpolate fractional crossing between i-1 and i.
            a = float(x[i - 1])
            b = float(x[i])
            denom = (a - b)
            frac = 0.0 if denom == 0.0 else (a / denom)
            idx = float(i - 1) + float(frac)
            idxs.append(idx)
            last_idx = idx
            armed = False

        return np.asarray(idxs, dtype=np.float64)

    def _classify_cycle(self, dist: float, *, gap0: float, gap1: float, gapn: float) -> Optional[int]:
        d0 = abs(float(dist) - float(gap0))
        d1 = abs(float(dist) - float(gap1))
        dn = abs(float(dist) - float(gapn))
        best = min(d0, d1, dn)
        if best > float(self.tol_samples):
            return None
        if best == dn:
            return None
        return 0 if best == d0 else 1

    def decode_bytes(
        self,
        audio_buffer: np.ndarray,
        *,
        expected_prefix: bytes | None = None,
        max_crc_pass_candidates: int = 4,
    ) -> Optional[bytes]:
        """Decode bytes payload, returns None if CRC fails or sync not found.

        `expected_prefix` (optional) mitigates CRC false-positives when decoding long/noisy
        audio: only payloads that begin with the given prefix are accepted.
        """
        x = np.asarray(audio_buffer, dtype=np.float32).reshape(-1)
        # DC removal improves zero-crossing stability under offsets and many audio pipelines.
        if x.size > 0:
            x = (x.astype(np.float64) - float(np.mean(x))).astype(np.float32)
        crossings = self._rising_zero_crossings(x)
        if crossings.size < 4:
            return None

        dists = np.diff(crossings)
        if dists.size < (self.preamble_cycles * self.symbol_cycles) + 16:
            return None

        gap0 = float(self.GAP_0)
        gap1 = float(self.GAP_1)
        gapn = float(self.GAP_NULL)

        # Find preamble: run of NULL-like cycles (closest to gap_null).
        # We use a sliding scoring window (tolerates a few bad cycles).
        pre = int(self.preamble_cycles) * int(self.symbol_cycles)
        tol = float(self.tol_samples)
        best_i = None
        best_score = -1
        for i in range(0, int(dists.size) - pre):
            window = dists[i : i + pre]
            score = int(np.sum(np.abs(window - gapn) <= tol))
            if score > best_score:
                best_score = score
                best_i = i

        if best_i is None or best_score < int(pre * 0.85):
            return None

        # Clock scale calibration from the best preamble window.
        pre_win = dists[int(best_i) : int(best_i) + pre]
        scale = float(np.median(pre_win) / gapn) if gapn > 0 else 1.0
        gap0 *= scale
        gap1 *= scale
        gapn *= scale

        start = int(best_i) + pre

        # Decode symbols after preamble using repetition groups.
        crc_pass = 0
        rx_bits: List[int] = []
        i = int(start)
        while i + int(self.symbol_cycles) <= int(dists.size):
            grp = dists[i : i + int(self.symbol_cycles)]
            i += int(self.symbol_cycles)

            # Per-cycle classification + majority vote (more robust under dropouts/jitter).
            votes_0 = 0
            votes_1 = 0
            for dist in grp.tolist():
                # During payload decode, keep alignment: always decide 0/1, never skip.
                # We still use tol to ignore obviously broken cycles, but we will always
                # produce a bit for the symbol group.
                dist_f = float(dist)
                d0 = abs(dist_f - float(gap0))
                d1 = abs(dist_f - float(gap1))
                if min(d0, d1) <= float(self.tol_samples):
                    if d0 <= d1:
                        votes_0 += 1
                    else:
                        votes_1 += 1

            # Fallback to mean nearest-neighbor between 0/1 (ignoring NULL) to preserve alignment.
            avg = float(np.mean(grp)) if grp.size else 0.0
            avg_d0 = abs(avg - float(gap0))
            avg_d1 = abs(avg - float(gap1))
            if votes_0 == votes_1:
                rx_bits.append(0 if avg_d0 <= avg_d1 else 1)
            else:
                rx_bits.append(0 if votes_0 > votes_1 else 1)

            # Opportunistic stop: if we already have header, stop when a full framed payload passes CRC.
            # To avoid CRC false-positives on long streams, optionally require `expected_prefix`.
            if len(rx_bits) >= (48 * int(self.fec_repeat)):  # 6 bytes header * 8, with repetition
                bits = self._fec_decode_bits(rx_bits)
                framed = self._bits_to_bytes(bits)
                payload = self._unframe_bytes(framed)
                if payload is not None:
                    if expected_prefix is None or payload.startswith(expected_prefix):
                        return payload
                    crc_pass += 1
                    if crc_pass >= int(max_crc_pass_candidates):
                        return None

        # Final attempt
        bits = self._fec_decode_bits(rx_bits)
        framed = self._bits_to_bytes(bits)
        payload = self._unframe_bytes(framed)
        if payload is None:
            return None
        if expected_prefix is not None and not payload.startswith(expected_prefix):
            return None
        return payload

    def decode(self, audio_buffer):
        payload = self.decode_bytes(audio_buffer)
        if payload is None:
            return ""
        try:
            return payload.decode("utf-8", errors="strict")
        except Exception:
            return payload.decode("utf-8", errors="replace")
