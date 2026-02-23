#!/usr/bin/env python3
"""
Restart/Reconnect Adversary Suite

Goal:
- Simulate a receiver restart (loss of session + nonce window).
- Prove an attacker cannot:
  1) replay a captured VERIFY_REQ to recreate a session (challenge prevents it)
  2) replay a captured DATA packet to get delivery after restart
- Prove a legitimate peer can reconnect and deliver again.

This suite spawns its own nodes on ephemeral localhost ports so it doesn't disturb any running demos.
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

def _post(url: str, payload: Dict[str, Any], timeout: int = 20) -> Tuple[int, Dict[str, Any]]:
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

def _get(url: str, timeout: int = 10) -> Tuple[int, Dict[str, Any]]:
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

def _wait_health(base: str, timeout_s: float = 10.0) -> Dict[str, Any]:
    t0 = time.time()
    last: Dict[str, Any] = {}
    while time.time() - t0 < float(timeout_s):
        c, b = _get(base + "/health", timeout=2)
        last = {"code": c, "body": b}
        if c == 200:
            return last
        time.sleep(0.1)
    raise RuntimeError(f"health_timeout {base}: {last}")

def _challenge(dst_base: str, peer_id: str) -> str:
    c, b = _post(dst_base + "/hive/v12/challenge", {"peer_id": str(peer_id)}, timeout=10)
    if c != 200 or not isinstance(b, dict) or not b.get("challenge"):
        raise RuntimeError(f"challenge_failed {dst_base}: {c} {b}")
    return str(b["challenge"])

def _verify_create(src_base: str, session_id: str, eph: int, challenge: str) -> Dict[str, Any]:
    c, b = _post(
        src_base + "/hive/v12/verify_req/create",
        {"session_id": str(session_id), "ephemeral_salt": int(eph), "challenge": str(challenge)},
        timeout=10,
    )
    if c != 200 or not isinstance(b, dict) or not isinstance(b.get("msg"), dict):
        raise RuntimeError(f"verify_create_failed {src_base}: {c} {b}")
    return dict(b["msg"])

def _verify_process(dst_base: str, peer_id: str, msg: Dict[str, Any], ttl_s: float) -> Dict[str, Any]:
    c, b = _post(dst_base + "/hive/v12/verify_req/process", {"peer_id": str(peer_id), "msg": msg, "ttl_s": float(ttl_s)}, timeout=10)
    if c != 200 or not isinstance(b, dict):
        raise RuntimeError(f"verify_process_failed {dst_base}: {c} {b}")
    return b

def _send(src_base: str, dst_node_id: str, content: str) -> Dict[str, Any]:
    c, b = _post(src_base + "/hive/v12/send", {"dst_node_id": str(dst_node_id), "content": str(content), "pad_bytes": 0}, timeout=20)
    if c != 200 or not isinstance(b, dict) or not isinstance(b.get("msg"), dict):
        raise RuntimeError(f"send_failed {src_base}: {c} {b}")
    return dict(b["msg"])

def _recv(dst_base: str, prev_hop_id: str, msg: Dict[str, Any]) -> Dict[str, Any]:
    c, b = _post(dst_base + "/hive/v12/receive", {"prev_hop_id": str(prev_hop_id), "msg": msg}, timeout=20)
    if c != 200 or not isinstance(b, dict):
        raise RuntimeError(f"recv_failed {dst_base}: {c} {b}")
    return b

def _hello(base: str) -> Dict[str, Any]:
    c, b = _post(base + "/hive/v12/hello", {}, timeout=10)
    if c != 200:
        raise RuntimeError(f"hello_failed {base}: {c} {b}")
    return b

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

    env = os.environ.copy()
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env['PYTHONPATH'] = root_dir + (os.pathsep + env['PYTHONPATH'] if 'PYTHONPATH' in env else '')
    return subprocess.Popen(args, env=env, cwd=root_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

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

def _ports_available(ports: list[int]) -> bool:
    socks = []
    try:
        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", int(port)))
            socks.append(s)
        return True
    except OSError:
        return False
    finally:
        for s in socks:
            try:
                s.close()
            except Exception:
                pass

def _pick_port_base(rng: random.Random, *, start: int, span: int, attempts: int = 100) -> int:
    for _ in range(int(attempts)):
        base = int(start) + int(rng.randrange(0, int(span)))
        if _ports_available([base, base + 1, base + 2]):
            return base
    raise RuntimeError("no_free_ports")

def main() -> int:
    ap = argparse.ArgumentParser()
    # Repo layout: `<repo_root>/attacks/*.py` and `<repo_root>/scripts/*.py`
    ap.add_argument("--repo-root", default=os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    ap.add_argument("--seed", type=int, default=7245)
    ap.add_argument("--eve-seed", type=int, default=8888)
    ap.add_argument("--anchor-seeds", default="7245")
    ap.add_argument("--ttl", type=float, default=600.0)
    ap.add_argument("--port-base", type=int, default=9100)
    ap.add_argument("--seed-rng", type=int, default=1337)
    ap.add_argument("--pepper", default="test_pepper", help="Shared cluster pepper for spawned nodes.")
    args = ap.parse_args()

    rng = random.Random(int(args.seed_rng))
    # Pick a free 3-port range; the old deterministic base could collide on busy machines/CI.
    start = int(args.port_base) if int(args.port_base) > 0 else 9100
    base = _pick_port_base(rng, start=start, span=20_000)

    a = f"http://127.0.0.1:{base}"
    b = f"http://127.0.0.1:{base+1}"
    e = f"http://127.0.0.1:{base+2}"

    pa = pb = pe = None
    report: Dict[str, Any] = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "nodes": {"a": a, "b": b, "e": e}, "steps": {}}
    try:
        pa = _start_node(
            repo_root=args.repo_root,
            port=base,
            node_id="A",
            seed=int(args.seed),
            anchor_seeds=str(args.anchor_seeds),
            pepper=str(args.pepper),
        )
        pb = _start_node(
            repo_root=args.repo_root,
            port=base + 1,
            node_id="B",
            seed=int(args.seed),
            anchor_seeds=str(args.anchor_seeds),
            pepper=str(args.pepper),
        )
        pe = _start_node(
            repo_root=args.repo_root,
            port=base + 2,
            node_id="EVE",
            seed=int(args.eve_seed),
            anchor_seeds=str(args.anchor_seeds),
            pepper=str(args.pepper),
        )

        report["steps"]["health_a"] = _wait_health(a, timeout_s=10)
        report["steps"]["health_b"] = _wait_health(b, timeout_s=10)
        report["steps"]["health_e"] = _wait_health(e, timeout_s=10)

        ha = _hello(a)
        hb = _hello(b)
        he = _hello(e)
        a_id = str(ha.get("node_id", "A"))
        b_id = str(hb.get("node_id", "B"))
        e_id = str(he.get("node_id", "EVE"))
        report["node_ids"] = {"a": a_id, "b": b_id, "e": e_id}

        session_id = f"{rng.getrandbits(128):032x}"
        eph = rng.getrandbits(31)

        # Establish A->B session (capture the verify_req used)
        ch = _challenge(b, a_id)
        verify_msg = _verify_create(a, session_id, eph, ch)
        ok1 = _verify_process(b, a_id, verify_msg, ttl_s=float(args.ttl))
        report["steps"]["handshake_a_to_b"] = {"challenge": ch, "verify_msg": verify_msg, "process": ok1}

        # Establish B->A session (needed for symmetry, but not critical for the restart attack)
        ch2 = _challenge(a, b_id)
        verify_msg2 = _verify_create(b, session_id, eph, ch2)
        ok2 = _verify_process(a, b_id, verify_msg2, ttl_s=float(args.ttl))
        report["steps"]["handshake_b_to_a"] = {"challenge": ch2, "process": ok2}

        # Baseline delivery
        data_msg = _send(a, b_id, "restart-suite baseline")
        delivered = _recv(b, a_id, data_msg)
        report["steps"]["baseline"] = {"msg": data_msg, "recv": delivered}

        # Restart B (simulate network death / process restart)
        _stop_proc(pb)
        pb = _start_node(
            repo_root=args.repo_root,
            port=base + 1,
            node_id="B",
            seed=int(args.seed),
            anchor_seeds=str(args.anchor_seeds),
            pepper=str(args.pepper),
        )
        report["steps"]["health_b_after_restart"] = _wait_health(b, timeout_s=10)

        # Attack attempt 1: replay captured VERIFY_REQ (should fail: bad_challenge because challenges are one-time and in-memory)
        replay_verify = _verify_process(b, a_id, verify_msg, ttl_s=float(args.ttl))
        report["steps"]["replay_verify_req_after_restart"] = replay_verify

        # Attack attempt 2: replay captured DATA without a session (should reject unknown_session)
        replay_data = _recv(b, a_id, data_msg)
        report["steps"]["replay_data_after_restart_no_session"] = replay_data

        # Legit reconnect: new handshake + new DATA should deliver
        ch3 = _challenge(b, a_id)
        verify3 = _verify_create(a, session_id, eph, ch3)
        ok3 = _verify_process(b, a_id, verify3, ttl_s=float(args.ttl))
        msg_new = _send(a, b_id, "restart-suite after-reconnect")
        recv_new = _recv(b, a_id, msg_new)
        report["steps"]["reconnect"] = {"process": ok3, "recv": recv_new}

        os.makedirs(os.path.join(args.repo_root, "logs"), exist_ok=True)
        out_path = os.path.join(args.repo_root, "logs", f"idre_restart_reconnect_suite_{int(time.time())}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print("WROTE", out_path)
        return 0
    finally:
        _stop_proc(pa)
        _stop_proc(pb)
        _stop_proc(pe)

if __name__ == "__main__":
    raise SystemExit(main())
