from __future__ import annotations

import sys
from pathlib import Path

# Repo root is the `idre_clean` package directory; add its parent so `import idre_clean.*` works.
_PKG_DIR = Path(__file__).resolve().parents[1]
_PARENT = _PKG_DIR.parent
if str(_PARENT) not in sys.path:
    sys.path.insert(0, str(_PARENT))

