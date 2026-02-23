#!/usr/bin/env python3
"""Vocab-enabled node timing test (A <-> B, no EVE).

Spawns 2 node servers on ephemeral ports with `--content-codec vocab` and measures:
- handshake timings (challenge + verify create/process)
- send + receive timings for a long message
- payload sizing (ct_len, payload ints)

This is a lab harness, not a CI test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Tuple
import threading


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


def _post_json(url: str, payload: Dict[str, Any], timeout: float = 15.0) -> Tuple[int, Dict[str, Any], float]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            dt_ms = (time.perf_counter() - t0) * 1000.0
            return int(r.getcode()), json.loads(r.read().decode("utf-8")), float(dt_ms)
    except urllib.error.HTTPError as exc:
        dt_ms = (time.perf_counter() - t0) * 1000.0
        body = exc.read().decode("utf-8", errors="replace")
        try:
            return int(exc.code), json.loads(body), float(dt_ms)
        except Exception:
            return int(exc.code), {"error": "http_error", "body": body}, float(dt_ms)
    except Exception as exc:
        dt_ms = (time.perf_counter() - t0) * 1000.0
        return 0, {"error": "exception", "detail": str(exc)}, float(dt_ms)


def _wait_health(base: str, timeout_s: float = 20.0) -> None:
    t0 = time.time()
    while True:
        code, _ = _get(base + "/health", timeout=2.0)
        if code == 200:
            return
        if time.time() - t0 > timeout_s:
            raise RuntimeError(f"health_timeout {base} last_code={code}")
        time.sleep(0.25)


def _handshake(a: str, a_id: str, b: str, b_id: str, *, session_id: str, e_salt: int, ttl_s: float) -> Dict[str, Any]:
    steps: Dict[str, Any] = {}

    # A -> B
    c0, b0, t0 = _post_json(b + "/hive/v12/challenge", {"peer_id": a_id}, timeout=10.0)
    steps["challenge_b_for_a"] = {"code": c0, "ms": t0}
    ch1 = b0.get("challenge") if isinstance(b0, dict) else None
    c1, b1, t1 = _post_json(
        a + "/hive/v12/verify_req/create",
        {"session_id": session_id, "ephemeral_salt": int(e_salt), "challenge": ch1},
        timeout=10.0,
    )
    steps["verify_create_a"] = {"code": c1, "ms": t1}
    msg1 = b1.get("msg")
    c2, b2, t2 = _post_json(
        b + "/hive/v12/verify_req/process", {"peer_id": a_id, "msg": msg1, "ttl_s": float(ttl_s)}, timeout=10.0
    )
    steps["verify_process_b"] = {"code": c2, "ms": t2, "verified": bool(b2.get("verified"))}

    # B -> A
    c3, b3, t3 = _post_json(a + "/hive/v12/challenge", {"peer_id": b_id}, timeout=10.0)
    steps["challenge_a_for_b"] = {"code": c3, "ms": t3}
    ch2 = b3.get("challenge") if isinstance(b3, dict) else None
    c4, b4, t4 = _post_json(
        b + "/hive/v12/verify_req/create",
        {"session_id": session_id, "ephemeral_salt": int(e_salt), "challenge": ch2},
        timeout=10.0,
    )
    steps["verify_create_b"] = {"code": c4, "ms": t4}
    msg2 = b4.get("msg")
    c5, b5, t5 = _post_json(
        a + "/hive/v12/verify_req/process", {"peer_id": b_id, "msg": msg2, "ttl_s": float(ttl_s)}, timeout=10.0
    )
    steps["verify_process_a"] = {"code": c5, "ms": t5, "verified": bool(b5.get("verified"))}

    return steps


def _reader_thread(p: subprocess.Popen, lines_out: "list[str]") -> None:
    if p.stdout is None:
        return
    for raw in p.stdout:
        try:
            lines_out.append(raw.decode("utf-8", errors="replace").rstrip("\r\n"))
        except Exception:
            continue


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vocab-file", default=r"F:\idre_clean\vocab.bin")
    ap.add_argument("--codec", default="vocab", choices=["vocab", "utf8"])
    ap.add_argument("--allow-literals", action=argparse.BooleanOptionalAction, default=False)
    ap.add_argument("--ttl", type=float, default=600.0)
    ap.add_argument("--pad-bytes", type=int, default=0)
    ap.add_argument("--message-file", default="", help="Optional UTF-8 text file; else uses built-in message.")
    args = ap.parse_args()

    if args.message_file:
        msg = Path(args.message_file).read_text(encoding="utf-8")
    else:
        msg = (
            "We introduce Integer-Dependent Receiver Encoding (IDRE), a cryptographic protocol\n"
            "designed for distributed cognitive architectures with stable attractor dynamics. Unlike\n"
            "traditional public-key infrastructure (PKI), IDRE does not rely on stored static keys or\n"
            "negotiated secrets. Instead, security emerges from the non-exportable geometry of inter-\n"
            "nal vector fields (attractors). The sender transmits a sequence of semantic-free integers\n"
            "that act as pointers to a shared, dynamic internal state. We formally define the decoding\n"
            "function Mt = Φ(St, It), demonstrating that without the precise topological configuration\n"
            "of the receiver’s attractor field, the intercepted integers are mathematically orthogonal to\n"
            "the plaintext. We present Test Vector 0002, validating the protocol under high-entropy\n"
            "permutation modes, showing 100% permutation drift and zero signal correlation in adver-\n"
            "sarial scenarios. This establishes IDRE as a viable candidate for ”Field-Bound Security” in\n"
            "bandwidth-constrained, high-latency environments."
        )

    repo_root = str(Path(__file__).resolve().parents[1])
    py = sys.executable
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    pepper = str(env.get("IDRE_PEPPER", "test_pepper"))

    port_a = _free_port()
    port_b = _free_port()
    a = f"http://127.0.0.1:{port_a}"
    b = f"http://127.0.0.1:{port_b}"

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
            "--pepper",
            pepper,
            "--freeze-field",
            "--content-codec",
            str(args.codec),
            "--vocab-file",
            str(args.vocab_file),
            "--vocab-allow-literals" if bool(args.allow_literals) else "--no-vocab-allow-literals",
        ],
        cwd=repo_root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        env=env,
    )
    lines_b: list[str] = []
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
            "--pepper",
            pepper,
            "--freeze-field",
            "--print-deliveries",
            "--content-codec",
            str(args.codec),
            "--vocab-file",
            str(args.vocab_file),
            "--vocab-allow-literals" if bool(args.allow_literals) else "--no-vocab-allow-literals",
        ],
        cwd=repo_root,
        stdout=subprocess.PIPE,  # capture deliveries
        stderr=subprocess.STDOUT,
        env=env,
    )
    t_b = threading.Thread(target=_reader_thread, args=(node_b_p, lines_b), daemon=True)
    t_b.start()

    try:
        _wait_health(a)
        _wait_health(b)

        # Optional: precompute codec plaintext size (token stream length) for sizing.
        codec_stats: Dict[str, Any] = {"codec": str(args.codec), "allow_literals": bool(args.allow_literals)}
        if str(args.codec) == "vocab":
            sys.path.insert(0, str(Path(repo_root).parent))
            from idre_clean.core.vocab_codec import decode_text, encode_text, load_vocab  # type: ignore

            v = load_vocab(str(args.vocab_file))
            blob = encode_text(str(msg), v, allow_literals=bool(args.allow_literals))
            ok, reason, out = decode_text(blob, v, allow_literals=bool(args.allow_literals))
            codec_stats.update(
                {
                    "vocab_plaintext_blob_bytes": len(blob),
                    "codec_roundtrip_ok": bool(ok),
                    "codec_roundtrip_reason": str(reason),
                    "codec_roundtrip_match": bool(out == str(msg)),
                }
            )

        # handshake
        session_id = hashlib.sha256(f"{time.time()}:{os.getpid()}".encode("utf-8")).hexdigest()[:32]
        e_salt = int.from_bytes(os.urandom(4), "big") & 0x7FFFFFFF
        hs = _handshake(a, "A", b, "B", session_id=session_id, e_salt=e_salt, ttl_s=float(args.ttl))

        # send
        c_send, b_send, t_send = _post_json(
            a + "/hive/v12/send",
            {"dst_node_id": "B", "content": str(msg), "pad_bytes": int(args.pad_bytes)},
            timeout=30.0,
        )
        if c_send != 200:
            report = {
                "status": "send_failed",
                "send": {"code": c_send, "body": b_send, "ms": t_send},
                "handshake": hs,
                "codec": codec_stats,
            }
            print(json.dumps(report, indent=2))
            return 2

        msg_obj = b_send.get("msg", {})
        payload = msg_obj.get("payload", [])
        ct_len = int(payload[0]) if isinstance(payload, list) and payload else -1
        payload_ints = len(payload) if isinstance(payload, list) else -1

        # receive (simulate network hop A->B)
        c_recv, b_recv, t_recv = _post_json(
            b + "/hive/v12/receive",
            {"prev_hop_id": "A", "msg": msg_obj},
            timeout=30.0,
        )

        # Pull a delivery line if present.
        delivered_line = ""
        t0 = time.time()
        while time.time() - t0 < 2.0:
            for s in lines_b[-50:]:
                if "[DELIVERED to B" in s:
                    delivered_line = s[:200] + ("..." if len(s) > 200 else "")
                    break
            if delivered_line:
                break
            time.sleep(0.05)

        report = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "nodes": {"a": a, "b": b},
            "session_id": session_id,
            "ephemeral_salt": e_salt,
            "codec": codec_stats,
            "handshake": hs,
            "send": {"code": c_send, "ms": t_send, "ct_len": ct_len, "payload_ints": payload_ints},
            "receive": {"code": c_recv, "ms": t_recv, "result": b_recv.get("result")},
            "delivered_line": delivered_line,
        }

        os.makedirs(os.path.join(repo_root, "logs"), exist_ok=True)
        out_path = os.path.join(repo_root, "logs", f"idre_vocab_timing_{int(time.time())}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        # Human summary
        total_hs = sum(float(v.get("ms", 0.0)) for v in hs.values() if isinstance(v, dict))
        print("WROTE", out_path)
        print("handshake_ms_total", round(total_hs, 2))
        print("send_ms", round(float(t_send), 2), "recv_ms", round(float(t_recv), 2))
        print("ct_len", ct_len, "payload_ints", payload_ints)
        print("deliver_status", report["receive"]["result"])
        return 0
    finally:
        for p in (node_a_p, node_b_p):
            try:
                if p.poll() is None:
                    p.terminate()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
