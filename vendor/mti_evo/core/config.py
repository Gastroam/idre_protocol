"""
Vendored MTI-EVO Configuration (minimal).

Copied from the local MTI-EVO codebase and trimmed to keep IDRE standalone stable.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Any, Dict, Mapping, Optional


def _default_engine_defaults() -> Dict[str, Dict[str, Any]]:
    return {
        "quantum": {"n_ctx": 8192, "gpu_layers": -1, "temperature": 0.7, "cache_type_k": "f16"},
        "gguf": {"n_ctx": 4096, "gpu_layers": 33, "temperature": 0.8, "cache_type_k": "q8_0"},
        "native": {"n_ctx": 2048, "gpu_layers": 0, "temperature": 0.7, "cache_type_k": "f16"},
        "api": {"n_ctx": 32768, "gpu_layers": 0, "temperature": 1.0, "cache_type_k": "f16"},
        "hybrid": {"n_ctx": 4096, "gpu_layers": -1, "temperature": 0.7, "mode": "local_first"},
        "auto": {"n_ctx": 4096, "gpu_layers": -1, "temperature": 0.7, "cache_type_k": "f16"},
    }


@dataclass
class MTIConfig:
    # --- Biological Physics (DNA) ---
    gravity: float = 20.0
    momentum: float = 0.9
    decay_rate: float = 0.15
    initial_lr: float = 0.5
    trainable_bias: bool = True
    weight_cap: float = 80.0
    diminishing_returns: bool = True
    passive_decay_rate: float = 0.00001
    random_seed: int = 1337
    deterministic: bool = True

    # --- Structural Architecture ---
    capacity_limit: int = 5000
    grace_period: int = 100
    embedding_dim: int = 64

    # --- Security / IDRE ---
    idre_anchor_seeds: tuple = (7245, 8888)
    pinned_seeds: set = field(default_factory=set)

    # --- Runtime / Engine (kept for compatibility) ---
    model_path: str = ""
    model_type: str = "auto"
    n_ctx: int = 8192
    temperature: float = 0.7
    max_tokens: int = 1024
    gpu_layers: int = -1
    engine_defaults: Dict[str, Dict[str, Any]] = field(default_factory=_default_engine_defaults)

    # Optional injection point (not used in standalone core)
    persistence_manager: Any = None

    @property
    def seed(self) -> int:
        return self.random_seed

    def to_dict(self, include_private: bool = False) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for f in fields(self):
            key = f.name
            if not include_private and key.startswith("_"):
                continue
            value = getattr(self, key)
            if key == "pinned_seeds":
                out[key] = sorted(list(value))
            elif key == "idre_anchor_seeds":
                out[key] = list(value)
            else:
                out[key] = value
        return out

    @classmethod
    def from_dict(cls, data: Optional[Mapping[str, Any]]) -> "MTIConfig":
        if data is None:
            return cls()
        if isinstance(data, cls):
            return data

        valid = {f.name for f in fields(cls)}
        payload: Dict[str, Any] = {}
        for key, value in dict(data).items():
            if key in valid:
                payload[key] = value

        if isinstance(payload.get("pinned_seeds"), list):
            payload["pinned_seeds"] = set(payload["pinned_seeds"])
        if isinstance(payload.get("idre_anchor_seeds"), list):
            payload["idre_anchor_seeds"] = tuple(payload["idre_anchor_seeds"])

        return cls(**payload)

    # Compatibility helpers
    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

