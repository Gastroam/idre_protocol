#!/usr/bin/env python3
"""
Rate Limit Suite (DoS Smoke Test)

Spawns a single node on an ephemeral localhost port and hammers:
- POST /hive/v12/challenge
- POST /hive/v12/verify_req/process

Goal: confirm the server returns 429 rate_limited under burst traffic and does not crash.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple


def _post(url: str, payload: Dict[str, Any], timeout: int = 10) -> Tuple[int, Dict[str, Any]]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(body)
        except Exception:
            return exc.code, {"error": "http_error", "status": exc.code, "body": body}
    except urllib.error.URLError as exc:
        return 0, {"error": "url_error", "reason": str(exc)}


def _get(url: str, timeout: int = 5) -> Tuple[int, Dict[str, Any]]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(body)
        except Exception:
            return exc.code, {"error": "http_error", "status": exc.code, "body": body}
    except urllib.error.URLError as exc:
        return 0, {"error": "url_error", "reason": str(exc)}


def _wait_health(base: str, timeout_s: float = 10.0) -> None:
    t0 = time.time()
    last = None
    while time.time() - t0 < float(timeout_s):
        c, b = _get(base + "/health", timeout=2)
        last = (c, b)
        if c == 200:
            return
        time.sleep(0.1)
    raise RuntimeError(f"health_timeout {base}: {last}")


def _start_node(
    *,
    repo_root: str,
    port: int,
    node_id: str,
    seed: int,
    anchor_seeds: str,
    pepper: str,
) -> subprocess.Popen:
    py = sys.executable
    args = [
        py,
        os.path.join(repo_root, "scripts", "hive_v12_node_server.py"),
        "--port",
        str(int(port)),
        "--node-id",
        str(node_id),
        "--seed",
        str(int(seed)),
        "--anchor-seeds",
        str(anchor_seeds),
        "--pepper",
        str(pepper),
        "--freeze-field",
        "--backend",
        "frozen",
    ]
    return subprocess.Popen(args, cwd=repo_root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _stop_proc(p: Optional[subprocess.Popen]) -> None:
    if p is None:
        return
    try:
        p.terminate()
    except Exception:
        pass
    try:
        p.wait(timeout=3)
        return
    except Exception:
        pass
    try:
        p.kill()
    except Exception:
        pass


def _port_available(port: int) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", int(port)))
        s.close()
        return True
    except OSError:
        try:
            s.close()
        except Exception:
            pass
        return False


def _pick_port(rng: random.Random, *, start: int, span: int, attempts: int = 200) -> int:
    for _ in range(int(attempts)):
        port = int(start) + int(rng.randrange(0, int(span)))
        if _port_available(port):
            return port
    raise RuntimeError("no_free_ports")


def main() -> int:
    ap = argparse.ArgumentParser()
    # Repo layout: `<repo_root>/attacks/*.py` and `<repo_root>/scripts/*.py`
    ap.add_argument("--repo-root", default=os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    ap.add_argument("--seed", type=int, default=7245)
    ap.add_argument("--anchor-seeds", default="7245")
    ap.add_argument("--port-base", type=int, default=9400)
    ap.add_argument("--seed-rng", type=int, default=1337)
    ap.add_argument("--n", type=int, default=200, help="Requests per hammer loop.")
    ap.add_argument("--pepper", default="test_pepper", help="Shared cluster pepper for spawned test node.")
    args = ap.parse_args()

    rng = random.Random(int(args.seed_rng))
    start = int(args.port_base) if int(args.port_base) > 0 else 9400
    port = _pick_port(rng, start=start, span=20_000)
    base = f"http://127.0.0.1:{port}"

    p = None
    report: Dict[str, Any] = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "node": base, "steps": {}}
    try:
        p = _start_node(
            repo_root=args.repo_root,
            port=port,
            node_id="A",
            seed=int(args.seed),
            anchor_seeds=str(args.anchor_seeds),
            pepper=str(args.pepper),
        )
        _wait_health(base, timeout_s=10)

        n = int(args.n)
        # Hammer /challenge
        codes = {}
        samples = []
        for i in range(n):
            c, b = _post(base + "/hive/v12/challenge", {"peer_id": f"P{i:05d}"}, timeout=5)
            codes[str(c)] = int(codes.get(str(c), 0)) + 1
            if len(samples) < 5 and c != 200:
                samples.append({"code": c, "body": b})
        report["steps"]["challenge_hammer"] = {"n": n, "codes": codes, "samples": samples}

        # Hammer /verify_req/process (invalid msg is fine; we only care about rate limiting and stability)
        codes2 = {}
        samples2 = []
        for i in range(n):
            c, b = _post(
                base + "/hive/v12/verify_req/process",
                {"peer_id": "X", "msg": {"type": "VERIFY_REQ"}, "ttl_s": 1.0},
                timeout=5,
            )
            codes2[str(c)] = int(codes2.get(str(c), 0)) + 1
            if len(samples2) < 5 and c != 200:
                samples2.append({"code": c, "body": b})
        report["steps"]["verify_process_hammer"] = {"n": n, "codes": codes2, "samples": samples2}

        # Confirm server is still alive
        hc, hb = _get(base + "/health", timeout=5)
        report["steps"]["health_after"] = {"code": hc, "body": hb}

        os.makedirs("logs", exist_ok=True)
        out_path = os.path.join("logs", f"idre_rate_limit_suite_{int(time.time())}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print("WROTE", out_path)
        return 0
    finally:
        _stop_proc(p)


if __name__ == "__main__":
    raise SystemExit(main())
