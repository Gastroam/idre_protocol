from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

import numpy as np

try:
    from idre_clean.core.physics_v12 import seeded_unit_vector
except Exception:  # pragma: no cover - fallback for script-style execution
    from core.physics_v12 import seeded_unit_vector


@dataclass(frozen=True)
class _FrozenNeuron:
    weights: np.ndarray
    bias: float = 0.0


class FrozenSubstrate:
    """Weights-only substrate for frozen backend (option A)."""

    def __init__(
        self,
        *,
        embedding_dim: int,
        seed_scales: Dict[int, float],
        bias: float = 0.0,
        folding_matrix: Optional[np.ndarray] = None,
    ):
        self.embedding_dim = int(embedding_dim)
        self.bias = float(bias)
        self._neurons: Dict[int, _FrozenNeuron] = {}

        for seed, scale in seed_scales.items():
            s = int(seed)
            sc = float(scale)

            w = seeded_unit_vector(s, self.embedding_dim) * sc
            # Fold in-memory to hide topology (row-vector convention).
            if folding_matrix is not None:
                w = np.dot(w, folding_matrix)

            self._neurons[s] = _FrozenNeuron(weights=w.astype(np.float64), bias=self.bias)

    def has(self, seed: int) -> bool:
        return int(seed) in self._neurons

    def get(self, seed: int) -> _FrozenNeuron:
        return self._neurons[int(seed)]


__all__ = ["FrozenSubstrate"]

