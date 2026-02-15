"""
Vendored MTI neuron primitive (minimal).

Only the parts needed to create/hold a neuron are required for IDRE, but
keeping perceive/adapt is useful for future experiments.
"""

from __future__ import annotations

import time
from typing import Any, Optional

import numpy as np

from .config import MTIConfig


class MTINeuron:
    def __init__(
        self,
        input_size: int,
        config: Optional[MTIConfig] = None,
        trainable_bias: bool = True,
        rng: Any = None,
        time_fn=None,
    ):
        if config is None:
            config = MTIConfig()

        if rng is None:
            seed = config.random_seed if getattr(config, "deterministic", True) else None
            rng = np.random.default_rng(seed)
        self.rng = rng
        self.time_fn = time_fn if time_fn else time.time

        self.weights = self.rng.normal(0.0, 0.05, size=(int(input_size),))
        self.bias = -2.0
        self.velocity = np.zeros(int(input_size), dtype=np.float64)

        self.gravity = float(config.gravity)
        self.momentum = float(config.momentum)
        self.initial_lr = float(config.initial_lr)
        self.decay_rate = float(config.decay_rate)
        self.trainable_bias = bool(trainable_bias)
        self.weight_cap = float(getattr(config, "weight_cap", 80.0))
        self.diminishing_returns = bool(getattr(config, "diminishing_returns", True))

        self.age = 0
        now = float(self.time_fn())
        self.last_accessed = now
        self.created_at = now

        self.label = None

    def _validate_inputs(self, inputs) -> np.ndarray:
        x = np.asarray(inputs)
        x = np.atleast_2d(x)
        expected_dim = int(self.weights.shape[0])
        if x.shape[1] != expected_dim:
            if x.size == expected_dim:
                x = x.reshape(-1, expected_dim)
            else:
                raise ValueError(f"Shape mismatch: expected {expected_dim}, got {x.shape}")
        return x

    def perceive(self, inputs) -> float:
        self.last_accessed = float(self.time_fn())
        x = self._validate_inputs(inputs)
        logits = np.dot(x, self.weights) + float(self.bias)
        y = 1.0 / (1.0 + np.exp(-logits))
        return float(y[0])

    def adapt(self, inputs, y_true: float = 1.0) -> None:
        self.age += 1
        self.last_accessed = float(self.time_fn())
        x = self._validate_inputs(inputs)
        y_pred = float(self.perceive(x))
        err = y_pred - float(y_true)

        lr = self.initial_lr / (1.0 + self.decay_rate * self.age)
        grad = x[0] * err

        self.velocity *= self.momentum
        self.velocity -= grad * lr
        self.weights += self.velocity

        if self.trainable_bias:
            self.bias -= lr * err

        n = float(np.linalg.norm(self.weights))
        if n > self.weight_cap:
            self.weights *= (self.weight_cap / n)
            self.velocity *= 0.5

