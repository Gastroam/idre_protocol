#!/usr/bin/env python3
"""Local end-to-end smoke test for the IDRE Gateway (fixed-size cells + cover traffic).

This is NOT a CI test. It spawns 2 node servers (A/B) and 2 gateways (GA/GB) on ephemeral
localhost ports, establishes an IDRE session, enqueues a message at GA, and waits for B to
print a delivery line.

Run:
  python attacks\\idre_gateway_smoke.py
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


REPO_PARENT = str(Path(__file__).resolve().parents[2])
if REPO_PARENT not in sys.path:
    sys.path.insert(0, REPO_PARENT)


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    _host, port = s.getsockname()
    s.close()
    return int(port)


def _get(url: str, timeout: float = 5.0) -> Tuple[int, Dict[str, Any]]:
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


def _post_json(url: str, payload: Dict[str, Any], timeout: float = 10.0) -> Tuple[int, Dict[str, Any]]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
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


def _wait_health(base: str, timeout_s: float = 15.0) -> None:
    t0 = time.time()
    while True:
        code, _ = _get(base + "/health", timeout=2.0)
        if code == 200:
            return
        if time.time() - t0 > timeout_s:
            raise RuntimeError(f"health_timeout {base} last_code={code}")
        time.sleep(0.25)


def _handshake(a: str, a_id: str, b: str, b_id: str, *, session_id: str, e_salt: int, ttl_s: float) -> None:
    # A -> B
    cc1, cb1 = _post_json(b + "/hive/v12/challenge", {"peer_id": a_id}, timeout=10.0)
    if cc1 != 200:
        raise RuntimeError(f"challenge_failed {b}: {cc1} {cb1}")
    ch1 = cb1.get("challenge")
    c1, b1 = _post_json(
        a + "/hive/v12/verify_req/create",
        {"session_id": session_id, "ephemeral_salt": int(e_salt), "challenge": ch1},
        timeout=10.0,
    )
    if c1 != 200:
        raise RuntimeError(f"verify_create_failed {a}: {c1} {b1}")
    msg1 = b1.get("msg")
    c2, b2 = _post_json(b + "/hive/v12/verify_req/process", {"peer_id": a_id, "msg": msg1, "ttl_s": ttl_s}, timeout=10.0)
    if c2 != 200:
        raise RuntimeError(f"verify_process_failed {b}: {c2} {b2}")
    if not bool(b2.get("verified")):
        raise RuntimeError(f"verify_failed {b}: {b2}")

    # B -> A
    cc3, cb3 = _post_json(a + "/hive/v12/challenge", {"peer_id": b_id}, timeout=10.0)
    if cc3 != 200:
        raise RuntimeError(f"challenge_failed {a}: {cc3} {cb3}")
    ch2 = cb3.get("challenge")
    c3, b3 = _post_json(
        b + "/hive/v12/verify_req/create",
        {"session_id": session_id, "ephemeral_salt": int(e_salt), "challenge": ch2},
        timeout=10.0,
    )
    if c3 != 200:
        raise RuntimeError(f"verify_create_failed {b}: {c3} {b3}")
    msg2 = b3.get("msg")
    c4, b4 = _post_json(a + "/hive/v12/verify_req/process", {"peer_id": b_id, "msg": msg2, "ttl_s": ttl_s}, timeout=10.0)
    if c4 != 200:
        raise RuntimeError(f"verify_process_failed {a}: {c4} {b4}")
    if not bool(b4.get("verified")):
        raise RuntimeError(f"verify_failed {a}: {b4}")


def _reader_thread(p: subprocess.Popen, tag: str, lines_out: "list[str]") -> None:
    assert p.stdout is not None
    for raw in p.stdout:
        try:
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        except Exception:
            continue
        lines_out.append(line)


def main() -> int:
    repo_root = str(Path(__file__).resolve().parents[1])

    port_a = _free_port()
    port_b = _free_port()
    port_ga = _free_port()
    port_gb = _free_port()

    node_a = f"http://127.0.0.1:{port_a}"
    node_b = f"http://127.0.0.1:{port_b}"
    gw_a = f"http://127.0.0.1:{port_ga}"
    gw_b = f"http://127.0.0.1:{port_gb}"

    py = sys.executable
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"

    node_a_p = subprocess.Popen(
        [
            py,
            "-u",
            str(Path(repo_root) / "scripts" / "hive_v12_node_server.py"),
            "--port",
            str(port_a),
            "--node-id",
            "A",
            "--seed",
            "7245",
            "--anchor-seeds",
            "7245",
            "--freeze-field",
        ],
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )
    node_b_p = subprocess.Popen(
        [
            py,
            "-u",
            str(Path(repo_root) / "scripts" / "hive_v12_node_server.py"),
            "--port",
            str(port_b),
            "--node-id",
            "B",
            "--seed",
            "7245",
            "--anchor-seeds",
            "7245",
            "--freeze-field",
            "--print-deliveries",
        ],
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )

    lines_a: list[str] = []
    lines_b: list[str] = []
    t_a = threading.Thread(target=_reader_thread, args=(node_a_p, "A", lines_a), daemon=True)
    t_b = threading.Thread(target=_reader_thread, args=(node_b_p, "B", lines_b), daemon=True)
    t_a.start()
    t_b.start()

    gw_a_p: Optional[subprocess.Popen] = None
    gw_b_p: Optional[subprocess.Popen] = None
    try:
        _wait_health(node_a)
        _wait_health(node_b)

        # Start gateways after nodes are up.
        gw_a_p = subprocess.Popen(
            [
                py,
                "-u",
                str(Path(repo_root) / "scripts" / "idre_gateway.py"),
                "--listen",
                f"127.0.0.1:{port_ga}",
                "--node",
                node_a,
                "--peer-cell-url",
                gw_b + "/cell",
                "--cell-len",
                "1536",
                "--tick-hz",
                "10",
                "--jitter-ms",
                "0",
            ],
            cwd=repo_root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
            env=env,
        )
        gw_b_p = subprocess.Popen(
            [
                py,
                "-u",
                str(Path(repo_root) / "scripts" / "idre_gateway.py"),
                "--listen",
                f"127.0.0.1:{port_gb}",
                "--node",
                node_b,
                "--peer-cell-url",
                gw_a + "/cell",
                "--cell-len",
                "1536",
                "--tick-hz",
                "10",
                "--jitter-ms",
                "0",
            ],
            cwd=repo_root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
            env=env,
        )

        # Gateways should be reachable.
        time.sleep(0.5)

        session_id = __import__("secrets").token_hex(16)
        e_salt = int.from_bytes(__import__("secrets").token_bytes(4), "big") & 0x7FFFFFFF
        _handshake(node_a, "A", node_b, "B", session_id=session_id, e_salt=e_salt, ttl_s=600.0)

        msg = f"gateway_smoke::{int(time.time())}"
        c, b = _post_json(gw_a + "/enqueue", {"dst_node_id": "B", "content": msg}, timeout=10.0)
        if c != 200 or not bool(b.get("enqueued")):
            raise RuntimeError(f"enqueue_failed {c} {b}")

        # Wait for B delivery print.
        deadline = time.time() + 8.0
        needle = f"[DELIVERED to B"
        while time.time() < deadline:
            for ln in lines_b[-50:]:
                if needle in ln and msg in ln:
                    print("OK: delivered via gateways")
                    return 0
            time.sleep(0.1)
        raise RuntimeError("timeout_waiting_for_delivery")
    finally:
        for p in (gw_a_p, gw_b_p):
            if p is not None and p.poll() is None:
                p.terminate()
        for p in (node_a_p, node_b_p):
            if p is not None and p.poll() is None:
                p.terminate()


if __name__ == "__main__":
    raise SystemExit(main())

