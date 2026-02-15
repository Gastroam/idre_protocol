from __future__ import annotations

import hashlib
from typing import List, Tuple

import numpy as np


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def derive_locked_plane(dims: int, domain: bytes = b"MTI/IDRE/PLANE") -> Tuple[np.ndarray, np.ndarray]:
    """Deterministic orthonormal plane basis (u, w)."""
    dims = int(dims)
    if dims < 1:
        raise ValueError("dims must be >= 1")
    if dims == 1:
        return np.array([1.0], dtype=np.float64), np.array([1.0], dtype=np.float64)

    seed = _sha256(domain + dims.to_bytes(4, "big", signed=False))
    rng = np.random.default_rng(int.from_bytes(seed[:8], "big", signed=False))

    u = rng.normal(0.0, 1.0, size=(dims,)).astype(np.float64)
    u /= float(np.linalg.norm(u) or 1.0)

    w = rng.normal(0.0, 1.0, size=(dims,)).astype(np.float64)
    w = w - (float(np.dot(w, u)) * u)
    w_norm = float(np.linalg.norm(w))
    if w_norm <= 1e-15:
        w = np.roll(u, 1)
        w_norm = float(np.linalg.norm(w))
    w /= w_norm

    return u, w


def seeded_unit_vector(seed_int: int, dims: int, domain: bytes = b"MTI/IDRE/ANCHOR") -> np.ndarray:
    """Deterministic unit vector derived from (seed_int, dims)."""
    seed_int = int(seed_int)
    dims = int(dims)
    if dims < 1:
        raise ValueError("dims must be >= 1")
    seed = _sha256(domain + seed_int.to_bytes(8, "big", signed=False) + dims.to_bytes(4, "big", signed=False))
    rng = np.random.default_rng(int.from_bytes(seed[:8], "big", signed=False))
    v = rng.normal(0.0, 1.0, size=(dims,)).astype(np.float64)
    n = float(np.linalg.norm(v))
    if n <= 1e-15:
        v = np.zeros((dims,), dtype=np.float64)
        v[0] = 1.0
        return v
    return v / n


def scan_fingerprint_bits(
    *,
    weights: np.ndarray,
    bias: float,
    tau: float,
    u: np.ndarray,
    w: np.ndarray,
    n_angles: int = 72,
    scan_resolution: int = 50,
    threshold: float = 0.5,
) -> List[int]:
    """Field fingerprint scan for a given neuron (weights,bias) projected onto a locked plane."""
    thetas = np.linspace(0.0, 2.0 * np.pi, int(n_angles), endpoint=False, dtype=np.float64)
    levels = np.linspace(0.02, 1.0, int(scan_resolution), dtype=np.float64)

    ww = np.asarray(weights, dtype=np.float64).reshape(-1)
    uu = np.asarray(u, dtype=np.float64).reshape(-1)
    ww2 = np.asarray(w, dtype=np.float64).reshape(-1)
    if ww.shape != uu.shape or ww.shape != ww2.shape:
        raise ValueError("weights/u/w shape mismatch")

    i_crit = np.zeros(int(n_angles), dtype=np.float64)
    for i, theta in enumerate(thetas):
        plane_v = (np.cos(theta) * uu) + (np.sin(theta) * ww2)
        found = 0.0
        for level in levels:
            resp = float(np.dot(plane_v * float(level), ww) + float(bias))
            if resp > float(tau):
                found = float(level)
                break
        i_crit[i] = found

    max_val = float(np.max(i_crit))
    if max_val <= 0.0:
        return [0] * int(n_angles)

    norm = i_crit / max_val
    bits = (norm > float(threshold)).astype(np.uint8)
    return [int(b) for b in bits.tolist()]

