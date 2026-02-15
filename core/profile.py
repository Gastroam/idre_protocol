from __future__ import annotations

import hashlib
from typing import Any, Dict

from .wire import canonical_json


def compute_field_profile_id(profile: Dict[str, Any]) -> str:
    """Public (non-secret) compatibility identifier."""
    return hashlib.sha256(canonical_json(profile)).hexdigest()[:16]

