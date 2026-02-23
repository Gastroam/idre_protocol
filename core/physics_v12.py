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
    """Deterministic integer plane basis (u, w). Pure Integer Geometry."""
    dims = int(dims)
    if dims < 1:
        raise ValueError("dims must be >= 1")
    if dims == 1:
        return np.array([1], dtype=np.int64), np.array([1], dtype=np.int64)

    seed = _sha256(bytes(domain) + dims.to_bytes(4, "big", signed=False))
    
    u_bytes = _expand_bytes(seed, dims * 2, b"U/")
    w_bytes = _expand_bytes(seed, dims * 2, b"W/")
    
    u = np.zeros(dims, dtype=np.int64)
    w = np.zeros(dims, dtype=np.int64)
    for i in range(dims):
        # Signed 8-bit mapping [-127, 127]
        u[i] = (int.from_bytes(u_bytes[i*2:i*2+2], "big", signed=False) % 255) - 127
        w[i] = (int.from_bytes(w_bytes[i*2:i*2+2], "big", signed=False) % 255) - 127
        
    return u, w

def seeded_unit_vector(seed_int: int, dims: int, domain: bytes = b"MTI/HIVE/V12/ANCHOR") -> np.ndarray:
    """Deterministic integer vector derived from (seed_int, dims)."""
    seed_int = int(seed_int)
    dims = int(dims)
    if dims < 1:
        raise ValueError("dims must be >= 1")
    seed = _sha256(bytes(domain) + seed_int.to_bytes(8, "big", signed=False) + dims.to_bytes(4, "big", signed=False))
    
    v_bytes = _expand_bytes(seed, dims * 2, b"V/")
    v = np.zeros(dims, dtype=np.int64)
    for i in range(dims):
        v[i] = (int.from_bytes(v_bytes[i*2:i*2+2], "big", signed=False) % 255) - 127
        
    if np.sum(np.abs(v)) == 0:
        v[0] = 1
    return v

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
    """Field fingerprint scan using discrete integer probes on the basis plane."""
    ww = np.asarray(weights, dtype=np.int64).reshape(-1)
    uu = np.asarray(u, dtype=np.int64).reshape(-1)
    ww2 = np.asarray(w, dtype=np.int64).reshape(-1)

    if unfolding_matrix is not None:
        uu = np.dot(uu, unfolding_matrix)
        ww2 = np.dot(ww2, unfolding_matrix)

    x = int(np.dot(uu, ww))
    y = int(np.dot(ww2, ww))
    bias_int = int(bias)

    resps = []
    for i in range(n_angles):
        # Deterministic pseudo-random coefficients for the plane
        h = hashlib.sha256(f"PROBE/{i}".encode()).digest()
        a = (int.from_bytes(h[:4], "big") % 21) - 10
        b = (int.from_bytes(h[4:8], "big") % 21) - 10
        if a == 0 and b == 0:
            a = 1
            
        # evaluate integer dot product exactly on the plane
        # including bias
        resp = a * x + b * y + bias_int
        resps.append(resp)
        
    max_resp = max(resps)
    if max_resp <= 0:
        return [0] * n_angles
        
    # Relative thresholding avoids floating point entirely
    # and restores true angular entropy shape
    threshold_val = int(max_resp * threshold)
    
    bits = [1 if r > threshold_val else 0 for r in resps]
    return bits


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
