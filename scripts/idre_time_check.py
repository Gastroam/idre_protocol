#!/usr/bin/env python3
"""Simple time sanity checker for IDRE nodes.

This does not make security claims. It's an operational tool to catch clock drift
that would otherwise cause `clock_skew` / `expired` rejects when time controls are enabled.
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Tuple

def _get_json(url: str, timeout: float = 5.0) -> Tuple[int, Dict[str, Any]]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return int(r.getcode()), json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            return int(exc.code), json.loads(body)
        except Exception:
            return int(exc.code), {"error": "http_error", "body": body}
    except Exception as exc:
        return 0, {"error": "exception", "detail": str(exc)}

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("nodes", nargs="+", help="Node base URLs, e.g. http://127.0.0.1:8890")
    ap.add_argument("--warn-ms", type=int, default=30_000, help="Warn if abs(offset) exceeds this many ms.")
    args = ap.parse_args()

    local_ms = int(time.time() * 1000.0)
    print("local_time_ms", local_ms)

    worst = 0
    for base in args.nodes:
        base = str(base).rstrip("/")
        code, body = _get_json(base + "/health", timeout=5.0)
        if code != 200:
            print("node", base, "health_failed", code, body.get("error") if isinstance(body, dict) else body)
            continue
        srv_ms = int(body.get("server_time_ms", 0) or 0)
        srv_utc = str(body.get("server_time_utc", ""))
        if srv_ms <= 0:
            print("node", base, "missing_server_time_ms")
            continue
        off = int(srv_ms) - int(local_ms)
        worst = max(worst, abs(int(off)))
        status = "OK" if abs(int(off)) <= int(args.warn_ms) else "WARN"
        print("node", base, "offset_ms", off, status, "server_time_utc", srv_utc)

    if int(worst) > int(args.warn_ms):
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

