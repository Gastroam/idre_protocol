#!/usr/bin/env python3
"""
Dual-node monitor for MTI-EVO/IDRE runtime.

Live checks:
- /status
- /api/idre/health
- periodic /v1/local/reflex probe on both nodes
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


def _http_json(url: str, method: str = "GET", payload: dict[str, Any] | None = None, timeout: int = 20) -> tuple[dict[str, Any] | None, str | None]:
    data = None
    headers = {"Content-Type": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url=url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw), None
    except urllib.error.HTTPError as exc:
        return None, f"http_{exc.code}"
    except urllib.error.URLError as exc:
        return None, f"url_error:{exc.reason}"
    except TimeoutError:
        return None, "timeout"
    except Exception as exc:  # pragma: no cover
        return None, f"error:{type(exc).__name__}:{exc}"


@dataclass
class NodeState:
    base: str
    status: str = "unknown"
    idre_enabled: bool = False
    idre_reason: str = "-"
    last_err: str = "-"
    reflex_hash: str = "-"
    reflex_tokens: int = 0
    reflex_latency_ms: float = 0.0
    reflex_resonance: float = 0.0


def _probe_node_health(node: NodeState) -> None:
    status_json, status_err = _http_json(f"{node.base}/status", timeout=10)
    idre_json, idre_err = _http_json(f"{node.base}/api/idre/health", timeout=10)

    if status_err:
        node.status = "down"
        node.last_err = status_err
    else:
        node.status = str((status_json or {}).get("status", "unknown"))
        node.last_err = "-"

    if idre_err:
        node.idre_enabled = False
        node.idre_reason = idre_err
    else:
        node.idre_enabled = bool((idre_json or {}).get("enabled", False))
        node.idre_reason = str((idre_json or {}).get("reason", (idre_json or {}).get("mode", "ok")))


def _probe_reflex(node: NodeState, prompt: str, seed: int, max_tokens: int, temperature: float, timeout: int) -> None:
    payload = {
        "action": "raw",
        "prompt": prompt,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "seed": seed,
        "learn": False,
        "symbiosis": False,
        "integer_communication": False,
        "timeout": timeout,
    }
    t0 = time.perf_counter()
    resp, err = _http_json(f"{node.base}/v1/local/reflex", method="POST", payload=payload, timeout=timeout + 10)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    if err:
        node.reflex_hash = f"err:{err}"
        node.reflex_tokens = 0
        node.reflex_latency_ms = elapsed_ms
        node.reflex_resonance = 0.0
        node.last_err = err
        return

    text = str((resp or {}).get("response", ""))
    node.reflex_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    node.reflex_tokens = int((resp or {}).get("tokens", 0) or 0)
    node.reflex_latency_ms = float((resp or {}).get("latency_ms", elapsed_ms) or elapsed_ms)
    node.reflex_resonance = float((resp or {}).get("resonance", 0.0) or 0.0)
    node.last_err = "-"


def _render_plain(now: str, n1: NodeState, n2: NodeState, probe_match: str, probe_count: int) -> None:
    print("=" * 110)
    print(f"[{now}] probe_count={probe_count} reflex_hash_match={probe_match}")
    print(f"A {n1.base:28} status={n1.status:8} idre_enabled={str(n1.idre_enabled):5} idre={n1.idre_reason:18} "
          f"lat_ms={n1.reflex_latency_ms:8.1f} tok={n1.reflex_tokens:4} res={n1.reflex_resonance:7.4f} err={n1.last_err}")
    print(f"B {n2.base:28} status={n2.status:8} idre_enabled={str(n2.idre_enabled):5} idre={n2.idre_reason:18} "
          f"lat_ms={n2.reflex_latency_ms:8.1f} tok={n2.reflex_tokens:4} res={n2.reflex_resonance:7.4f} err={n2.last_err}")
    print(f"A_hash={n1.reflex_hash}")
    print(f"B_hash={n2.reflex_hash}")


def run(args: argparse.Namespace) -> int:
    node_a = NodeState(base=args.node_a.rstrip("/"))
    node_b = NodeState(base=args.node_b.rstrip("/"))
    loops = 0
    probe_count = 0
    print("Starting dual-node monitor. Press Ctrl+C to stop.")

    try:
        while True:
            loops += 1
            now = time.strftime("%Y-%m-%d %H:%M:%S")

            _probe_node_health(node_a)
            _probe_node_health(node_b)

            do_probe = (loops == 1) or (args.probe_every > 0 and (loops % args.probe_every == 0))
            if do_probe:
                probe_count += 1
                _probe_reflex(node_a, args.prompt, args.seed, args.max_tokens, args.temperature, args.request_timeout)
                _probe_reflex(node_b, args.prompt, args.seed, args.max_tokens, args.temperature, args.request_timeout)

            match = "n/a"
            if node_a.reflex_hash != "-" and node_b.reflex_hash != "-":
                match = str(node_a.reflex_hash == node_b.reflex_hash)

            _render_plain(now, node_a, node_b, match, probe_count)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")
        return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Real-time dual-node monitor for IDRE/MTI server instances.")
    p.add_argument("--node-a", default="http://127.0.0.1:8814", help="Node A base URL")
    p.add_argument("--node-b", default="http://127.0.0.1:8815", help="Node B base URL")
    p.add_argument("--interval", type=int, default=3, help="Seconds between status refreshes")
    p.add_argument("--probe-every", type=int, default=5, help="Run reflex probe every N refresh loops")
    p.add_argument("--request-timeout", type=int, default=120, help="HTTP timeout for probe requests")
    p.add_argument("--seed", type=int, default=424242, help="Seed used in reflex probe")
    p.add_argument("--max-tokens", type=int, default=180, help="max_tokens for reflex probe")
    p.add_argument("--temperature", type=float, default=0.2, help="temperature for reflex probe")
    p.add_argument(
        "--prompt",
        default="Explain in 5 precise bullets how quantum decoherence differs from wavefunction collapse.",
        help="Prompt used in periodic reflex probe",
    )
    return p.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(run(parse_args(sys.argv[1:])))
