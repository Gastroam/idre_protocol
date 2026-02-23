import numpy as np
import hashlib
from typing import Tuple, Optional, List

def _expand_bytes(seed: bytes, n: int, domain: bytes) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < int(n):
        out.extend(hashlib.sha256(domain + seed + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(out[: int(n)])

def deterministic_shuffle_and_signs(dim: int, seed: int) -> Tuple[List[int], List[int]]:
    s_bytes = seed.to_bytes(8, "big", signed=False)
    stream = _expand_bytes(s_bytes, dim * 4, b"TOPOLOGY/FOLD/")
    
    perm = list(range(dim))
    signs = [1] * dim
    
    # Fisher-Yates with SHA256 entropy
    for i in range(dim - 1, 0, -1):
        idx = i * 4
        rand_val = int.from_bytes(stream[idx:idx+4], "big")
        j = rand_val % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
        
    stream_signs = _expand_bytes(s_bytes, dim, b"TOPOLOGY/SIGNS/")
    for i in range(dim):
        if stream_signs[i] % 2 == 0:
            signs[i] = -1
            
    return perm, signs

def generate_orthonormal_matrix(dim: int, seed: int) -> np.ndarray:
    """
    Generate a deterministic random orthonormal matrix (Signed Permutation).
    Used as the Folding Matrix P_fold. Pure Integer Geometry.
    """
    if dim < 1:
        raise ValueError("dim must be >= 1")
    
    perm, signs = deterministic_shuffle_and_signs(dim, seed)
    P = np.zeros((dim, dim), dtype=np.int64)
    for i in range(dim):
        P[i, perm[i]] = signs[i]
        
    return P

def fold_vector(v: np.ndarray, P_fold: np.ndarray) -> np.ndarray:
    """
    Apply Folding: v_fold = v_true @ P_fold
    """
    return np.dot(v, P_fold)

def unfold_basis(u: np.ndarray, w: np.ndarray, P_fold: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """
    Map basis vectors into the folded coordinate system for probing folded weights.

    Folding convention in this repo is row-vectors: `v_fold = v_true @ P_fold`.
    So probe basis vectors must be transformed the same way.
    """
    u_prime = np.dot(u, P_fold)
    w_prime = np.dot(w, P_fold)
    return u_prime, w_prime

class TopologyManager:
    """
    Manages the 'Ghost Topology' (Vector Space Folding).
    Generates the Folding Matrix P_fold from a seed.
    Derives the Unfolding Matrix P_unfold (Inverse) for probing.
    """
    def __init__(self, seed: int, dim: int):
        self.seed = seed
        self.dim = dim
        self._P_fold: Optional[np.ndarray] = None
        self._P_unfold: Optional[np.ndarray] = None
        
        # Initialize immediately for MVP (In real IDRE v3, P_fold might be hardware-bound)
        self._generate_matrices()

    def _generate_matrices(self):
        self._P_fold = generate_orthonormal_matrix(self.dim, self.seed)
        # Unfolding requires rotating the Probe Plane by P_fold to match the Folded Space
        # So P_unfold is the SAME as P_fold (Rotation Matrix)
        self._P_unfold = self._P_fold

    @property
    def folding_matrix(self) -> np.ndarray:
        if self._P_fold is None:
            self._generate_matrices()
        return self._P_fold

    @property
    def unfolding_matrix(self) -> np.ndarray:
        if self._P_unfold is None:
            self._generate_matrices()
        return self._P_unfold

    def fold_substrate(self, weights: np.ndarray) -> np.ndarray:
        """
        Fold a weight matrix (Row vectors).
        W_folded = W_true @ P_fold
        """
        return np.dot(weights, self.folding_matrix)

