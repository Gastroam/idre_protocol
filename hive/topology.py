import numpy as np
import hashlib
from typing import Tuple, Optional

def generate_orthonormal_matrix(dim: int, seed: int) -> np.ndarray:
    """
    Generate a deterministic random orthonormal matrix (Rotation/Reflection).
    Used as the Folding Matrix P_fold.
    """
    if dim < 1:
        raise ValueError("dim must be >= 1")
    
    # Deterministic RNG
    s_bytes = seed.to_bytes(8, "big", signed=False)
    rng_seed = int.from_bytes(hashlib.sha256(b"TOPOLOGY/FOLD/" + s_bytes).digest()[:8], "big")
    rng = np.random.default_rng(rng_seed)
    
    # Generate random matrix
    X = rng.normal(0.0, 1.0, size=(dim, dim))
    
    # QR Decomposition to get Orthogonal Q
    Q, R = np.linalg.qr(X)
    
    # Ensure determinism (QR phase can vary, strictly enforce diagonal of R positive)
    # This is standard trick to make QR unique
    d = np.diagonal(R)
    ph = np.sign(d)
    Q *= ph
    
    return Q

def fold_vector(v: np.ndarray, P_fold: np.ndarray) -> np.ndarray:
    """
    Apply Folding: v_fold = v_true @ P_fold
    """
    return np.dot(v, P_fold)

def unfold_basis(u: np.ndarray, w: np.ndarray, P_fold: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """
    Derive Unfolded Basis for Probing:
    u_prime = u @ P_unfold
    w_prime = w @ P_unfold
    
    Where P_unfold = inv(P_fold) = P_fold.T (since Orthogonal)
    """
    # Inverse of Orthogonal Matrix is Transpose
    P_unfold = P_fold.T 
    
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

