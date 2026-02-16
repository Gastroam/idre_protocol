from __future__ import annotations

from typing import List, Tuple

import numpy as np

from .physics_v12 import derive_locked_plane, scan_fingerprint_bits, seeded_unit_vector


def derive_locked_planes_v12(dims: int, n_planes: int) -> List[Tuple[np.ndarray, np.ndarray]]:
    n_planes = int(n_planes)
    if n_planes < 1:
        raise ValueError("n_planes must be >= 1")
    out: List[Tuple[np.ndarray, np.ndarray]] = []
    for i in range(n_planes):
        out.append(derive_locked_plane(int(dims), domain=b"MTI/HIVE/V12/PLANE/" + i.to_bytes(2, "big")))
    return out


def compute_fingerprint_bits_frozen_v12(
    *,
    seed: int,
    embedding_dim: int = 64,
    planes: int = 4,
    tau_frac: float = 0.55,
    n_angles: int = 72,
    scan_resolution: int = 50,
    threshold: float = 0.5,
    anchor_weight: float = 80.0,
) -> List[int]:
    """
    Deterministic fingerprint bits for the frozen backend.

    Matches the logic in `scripts/hive_v12_node_server.py`:
    - weights = unit_vector(seed) * anchor_weight
    - for each locked plane: tau = projection_amp(weights) * tau_frac
    - scan fingerprint bits
    """
    seed = int(seed)
    embedding_dim = int(embedding_dim)
    ww = seeded_unit_vector(seed, embedding_dim, domain=b"MTI/HIVE/V12/ANCHOR").astype(np.float64) * float(anchor_weight)
    bias = 0.0

    bits: List[int] = []
    for plane_idx, (u, w) in enumerate(derive_locked_planes_v12(embedding_dim, planes)):
        a = float(np.dot(np.asarray(u, dtype=np.float64).reshape(-1), ww))
        b = float(np.dot(np.asarray(w, dtype=np.float64).reshape(-1), ww))
        amp = float(np.hypot(a, b))
        tau = float(max(amp * float(tau_frac), 1e-9))
        bits.extend(
            scan_fingerprint_bits(
                weights=ww,
                bias=bias,
                tau=tau,
                u=u,
                w=w,
                n_angles=int(n_angles),
                scan_resolution=int(scan_resolution),
                threshold=float(threshold),
            )
        )
    return bits
