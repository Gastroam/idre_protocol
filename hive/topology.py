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
    
    u_prime = np.dot(u, P_unfold)
    w_prime = np.dot(w, P_unfold)
    
    return u_prime, w_prime
