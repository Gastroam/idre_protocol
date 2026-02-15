"""
Vendored HolographicLattice (minimal).

This is a tiny subset of MTI-EVO's lattice that IDRE needs:
- active_tissue: dict(seed -> MTINeuron)
- stimulate(): ensure neurons exist, optionally learn

No telemetry, no persistence, no plugins, no eviction.
"""

from __future__ import annotations

import time
from typing import Dict, Iterable, Optional

import numpy as np

from .config import MTIConfig
from .neuron import MTINeuron


class HolographicLattice:
    def __init__(self, config: Optional[MTIConfig] = None, time_fn=None):
        self.config = config or MTIConfig()
        self.time_fn = time_fn if time_fn else time.time

        seed = getattr(self.config, "random_seed", 1337)
        if not getattr(self.config, "deterministic", True):
            seed = None
        self.rng = np.random.default_rng(seed)

        self.active_tissue: Dict[int, MTINeuron] = {}
        self.capacity_limit = int(getattr(self.config, "capacity_limit", 5000))
        self.grace_period = int(getattr(self.config, "grace_period", 100))

    def stimulate(self, seed_stream: Iterable[int], input_signal, learn: bool = True):
        x_in = np.atleast_2d(input_signal)
        input_size = int(x_in.shape[1])

        last_resp = 0.0
        for seed in seed_stream:
            sid = int(seed)
            n = self.active_tissue.get(sid)
            if n is None:
                n = MTINeuron(input_size, config=self.config, rng=self.rng, time_fn=self.time_fn)
                self.active_tissue[sid] = n

            last_resp = float(n.perceive(x_in[0]))
            if learn:
                # For IDRE uses, learning is typically disabled/frozen.
                n.adapt(x_in[0], y_true=1.0)

        return last_resp

