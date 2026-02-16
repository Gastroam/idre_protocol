from __future__ import annotations

import hashlib
from typing import List, Optional, Tuple

import numpy as np


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _expand_bytes(seed: bytes, n: int, domain: bytes) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < int(n):
        out.extend(_sha256(domain + seed + counter.to_bytes(4, "big")))
        counter += 1
    return bytes(out[: int(n)])


def derive_locked_plane(dims: int, domain: bytes = b"MTI/HIVE/V12/PLANE") -> Tuple[np.ndarray, np.ndarray]:
    """Deterministic orthonormal plane basis (u, w)."""
    dims = int(dims)
    if dims < 1:
        raise ValueError("dims must be >= 1")
    if dims == 1:
        return np.array([1.0], dtype=np.float64), np.array([1.0], dtype=np.float64)

    seed = _sha256(bytes(domain) + dims.to_bytes(4, "big", signed=False))
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


def seeded_unit_vector(seed_int: int, dims: int, domain: bytes = b"MTI/HIVE/V12/ANCHOR") -> np.ndarray:
    """Deterministic unit vector derived from (seed_int, dims)."""
    seed_int = int(seed_int)
    dims = int(dims)
    if dims < 1:
        raise ValueError("dims must be >= 1")
    seed = _sha256(bytes(domain) + seed_int.to_bytes(8, "big", signed=False) + dims.to_bytes(4, "big", signed=False))
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
    unfolding_matrix: Optional[np.ndarray] = None,
) -> List[int]:
    """Field fingerprint scan for a given neuron (weights,bias) projected onto a locked plane."""
    ww = np.asarray(weights, dtype=np.float64).reshape(-1)
    uu = np.asarray(u, dtype=np.float64).reshape(-1)
    ww2 = np.asarray(w, dtype=np.float64).reshape(-1)
    if ww.shape != uu.shape or ww.shape != ww2.shape:
        raise ValueError("weights/u/w shape mismatch")

    # Topology unfolding: rotate the probe plane (u, w).
    if unfolding_matrix is not None:
        uu = np.dot(uu, unfolding_matrix)
        ww2 = np.dot(ww2, unfolding_matrix)

    thetas = np.linspace(0.0, 2.0 * np.pi, int(n_angles), endpoint=False, dtype=np.float64)
    levels = np.linspace(0.02, 1.0, int(scan_resolution), dtype=np.float64)

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


def derive_locked_planes(dims: int, n_planes: int) -> List[Tuple[np.ndarray, np.ndarray]]:
    n_planes = int(n_planes)
    if n_planes < 1:
        raise ValueError("n_planes must be >= 1")
    planes: List[Tuple[np.ndarray, np.ndarray]] = []
    for i in range(n_planes):
        planes.append(derive_locked_plane(int(dims), domain=b"MTI/HIVE/V12/PLANE/" + i.to_bytes(2, "big")))
    return planes


def compute_block_salt(bits: List[int], session_id: str, block_index: int) -> bytes:
    bitstring = "".join(str(int(b) & 1) for b in bits)
    raw = f"{bitstring}:{session_id}:{int(block_index)}".encode("utf-8")
    return _sha256(raw)


def derive_keystream_and_permutation(salt: bytes, block_len: int) -> Tuple[List[int], List[int]]:
    """Derive (keystream bytes, permutation indices) from a per-block salt."""
    block_len = int(block_len)
    ks = _expand_bytes(bytes(salt), block_len, b"K/")
    k_t = [int(b) & 0xFF for b in ks]

    # Use a per-position rank to avoid tie-heavy permutations.
    ranks = []
    for i in range(block_len):
        r = _sha256(b"P/" + bytes(salt) + i.to_bytes(2, "big"))
        ranks.append((r, i))
    ranks.sort(key=lambda x: x[0])
    pi_t = [i for _r, i in ranks]
    return k_t, pi_t


def permute(block: List[int], pi_t: List[int]) -> List[int]:
    return [int(block[i]) & 0xFF for i in pi_t]


def inverse_permute(block: List[int], pi_t: List[int]) -> List[int]:
    out = [0] * len(pi_t)
    for i, target in enumerate(pi_t):
        out[int(target)] = int(block[i]) & 0xFF
    return out


def xor_bytes(a: List[int], b: List[int]) -> List[int]:
    return [(int(x) ^ int(y)) & 0xFF for x, y in zip(a, b)]
