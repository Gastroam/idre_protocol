#!/usr/bin/env python3
"""Hive v1.2 + field-bound IDRE workflow demo (NO idre-protocol).

This script drives two running node servers (see `scripts/hive_v12_node_server.py`) and
exercises a minimal threat model:
- baseline delivery
- intercept + append-noise (should still decode because of ciphertext framing)
- intercept + in-band tamper (should fail integrity)
- replay (should be rejected)

Security posture:
- We do not request any internal field state over HTTP.
- Nodes never return plaintext; delivery is optionally printed in the node console.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import random
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Tuple


def _get(url: str, timeout: int = 30) -> Tuple[int, Dict[str, Any]]:
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


def _post(url: str, payload: Dict[str, Any], timeout: int = 60) -> Tuple[int, Dict[str, Any]]:
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


def _sha256_json(obj: Any) -> str:
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _append_noise(msg: Dict[str, Any], n: int, rng: random.Random) -> Dict[str, Any]:
    out = copy.deepcopy(msg)
    payload = out.get("payload")
    if isinstance(payload, list):
        payload.extend([rng.getrandbits(8) for _ in range(max(0, int(n)))])
    return out


def _flip_inband(msg: Dict[str, Any], rng: random.Random) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Flip a byte inside the framed ciphertext region.

    Wire format is: payload = [ct_len, ct_bytes..., pad_bytes...]
    We mutate one byte within ct_bytes so unframing includes the modified value.
    """
    out = copy.deepcopy(msg)
    payload = out.get("payload")
    if not isinstance(payload, list) or not payload:
        return out, {"warning": "no_payload"}

    ct_len = int(payload[0])
    if ct_len <= 0:
        return out, {"warning": "ct_len<=0", "ct_len": ct_len}

    # Choose an index within ciphertext bytes.
    start = 1
    end = min(1 + ct_len, len(payload))
    if end <= start:
        return out, {"warning": "bad_range", "ct_len": ct_len, "payload_len": len(payload)}

    idx = rng.randrange(start, end)
    before = int(payload[idx]) & 0xFF
    payload[idx] = (before ^ 0x5A) & 0xFF
    return out, {"index": idx, "before": before, "after": int(payload[idx]), "xor": 0x5A, "ct_len": ct_len}


def _tamper_header(msg: Dict[str, Any], field: str, new_value: Any) -> Dict[str, Any]:
    out = copy.deepcopy(msg)
    out[field] = new_value
    return out


def _hello(base: str) -> Dict[str, Any]:
    code, body = _post(base + "/hive/v12/hello", {}, timeout=10)
    if code != 200:
        raise RuntimeError(f"hello_failed {base}: {code} {body}")
    return body


def _handshake(a: str, a_id: str, b: str, b_id: str, *, session_id: str, e_salt: int, ttl_s: float) -> Dict[str, Any]:
    # A -> B
    cc1, cb1 = _post(b + "/hive/v12/challenge", {"peer_id": a_id}, timeout=30)
    if cc1 != 200:
        raise RuntimeError(f"challenge_failed {b}: {cc1} {cb1}")
    ch1 = cb1.get("challenge") if isinstance(cb1, dict) else None
    c1, b1 = _post(a + "/hive/v12/verify_req/create", {"session_id": session_id, "ephemeral_salt": e_salt, "challenge": ch1}, timeout=30)
    if c1 != 200:
        raise RuntimeError(f"verify_create_failed {a}: {c1} {b1}")
    msg1 = b1.get("msg")

    c2, b2 = _post(b + "/hive/v12/verify_req/process", {"peer_id": a_id, "msg": msg1, "ttl_s": ttl_s}, timeout=30)
    if c2 != 200:
        raise RuntimeError(f"verify_process_failed {b}: {c2} {b2}")

    # B -> A
    cc3, cb3 = _post(a + "/hive/v12/challenge", {"peer_id": b_id}, timeout=30)
    if cc3 != 200:
        raise RuntimeError(f"challenge_failed {a}: {cc3} {cb3}")
    ch2 = cb3.get("challenge") if isinstance(cb3, dict) else None
    c3, b3 = _post(b + "/hive/v12/verify_req/create", {"session_id": session_id, "ephemeral_salt": e_salt, "challenge": ch2}, timeout=30)
    if c3 != 200:
        raise RuntimeError(f"verify_create_failed {b}: {c3} {b3}")
    msg2 = b3.get("msg")

    c4, b4 = _post(a + "/hive/v12/verify_req/process", {"peer_id": b_id, "msg": msg2, "ttl_s": ttl_s}, timeout=30)
    if c4 != 200:
        raise RuntimeError(f"verify_process_failed {a}: {c4} {b4}")

    return {
        "a_to_b": {"create": {"code": c1, "ok": b1.get("status") == "ok"}, "process": b2},
        "b_to_a": {"create": {"code": c3, "ok": b3.get("status") == "ok"}, "process": b4},
    }


def _send(a: str, dst_id: str, content: str, pad_bytes: int) -> Dict[str, Any]:
    c, b = _post(a + "/hive/v12/send", {"dst_node_id": dst_id, "content": content, "pad_bytes": pad_bytes}, timeout=60)
    if c != 200:
        raise RuntimeError(f"send_failed {a}: {c} {b}")
    msg = b.get("msg")
    if not isinstance(msg, dict):
        raise RuntimeError(f"send_bad_msg {a}: {b}")
    return msg


def _receive(b: str, prev_id: str, msg: Dict[str, Any]) -> Dict[str, Any]:
    c, body = _post(b + "/hive/v12/receive", {"prev_hop_id": prev_id, "msg": msg}, timeout=60)
    if c != 200:
        raise RuntimeError(f"receive_failed {b}: {c} {body}")
    return body


def _write_log(report: Dict[str, Any]) -> str:
    os.makedirs("logs", exist_ok=True)
    out_path = os.path.join("logs", f"hive_v12_full_workflow_{int(time.time())}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return out_path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--node-a", default="http://127.0.0.1:8890")
    ap.add_argument("--node-b", default="http://127.0.0.1:8891")
    ap.add_argument(
        "--node-e",
        default="",
        help="Optional EVE node base URL (e.g. http://127.0.0.1:8892). Used to prove handshake failure + inability to receive.",
    )
    ap.add_argument("--message", default="Meet at 0300Z. Contract TV0001.")
    ap.add_argument("--pad-bytes", type=int, default=0, help="extra bytes appended to the framed ciphertext")
    ap.add_argument("--noise-bytes", type=int, default=64, help="attacker appended payload bytes")
    ap.add_argument("--seed", type=int, default=1337, help="deterministic seed for demo")
    ap.add_argument("--ttl", type=float, default=600.0)
    args = ap.parse_args()

    a = args.node_a.rstrip("/")
    b = args.node_b.rstrip("/")
    e = args.node_e.rstrip("/") if str(args.node_e).strip() else ""

    # preflight
    hc_a, _ = _get(a + "/health")
    hc_b, _ = _get(b + "/health")
    if hc_a != 200 or hc_b != 200:
        raise RuntimeError(f"health_failed a={hc_a} b={hc_b}")

    hello_a = _hello(a)
    hello_b = _hello(b)
    a_id = str(hello_a.get("node_id", "A"))
    b_id = str(hello_b.get("node_id", "B"))
    e_id = ""
    if e:
        try:
            hc_e, _ = _get(e + "/health")
            if hc_e == 200:
                hello_e = _hello(e)
                e_id = str(hello_e.get("node_id", "EVE"))
        except Exception:
            e = ""

    rng = random.Random(int(args.seed))
    session_id = hashlib.sha256(f"{time.time()}:{rng.getrandbits(64)}".encode("utf-8")).hexdigest()[:32]
    e_salt = rng.getrandbits(31)

    report: Dict[str, Any] = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "node_a": a,
        "node_b": b,
        "node_e": e or None,
        "node_ids": {"a": a_id, "b": b_id},
        "session_id": session_id,
        "ephemeral_salt": e_salt,
        "pad_bytes": int(args.pad_bytes),
        "steps": {},
    }
    if e and e_id:
        report["node_ids"]["e"] = e_id

    # handshake
    report["steps"]["handshake"] = _handshake(a, a_id, b, b_id, session_id=session_id, e_salt=e_salt, ttl_s=float(args.ttl))

    # Optional: EVE mismatch should fail verification in both directions.
    if e and e_id:
        eve = {"a_process_eve": None, "eve_process_a": None}
        try:
            # EVE -> A verify request, A should reject (verified=False).
            cc1, cb1 = _post(a + "/hive/v12/challenge", {"peer_id": e_id}, timeout=30)
            ch_e = cb1.get("challenge") if isinstance(cb1, dict) else None
            c1, b1 = _post(e + "/hive/v12/verify_req/create", {"session_id": session_id, "ephemeral_salt": e_salt, "challenge": ch_e}, timeout=30)
            msg_e = b1.get("msg") if isinstance(b1, dict) else None
            c2, b2 = _post(a + "/hive/v12/verify_req/process", {"peer_id": e_id, "msg": msg_e, "ttl_s": float(args.ttl)}, timeout=30)
            eve["a_process_eve"] = {"create": {"code": c1, "body": b1}, "process": {"code": c2, "body": b2}}

            # A -> EVE verify request, EVE should reject.
            cc3, cb3 = _post(e + "/hive/v12/challenge", {"peer_id": a_id}, timeout=30)
            ch_a = cb3.get("challenge") if isinstance(cb3, dict) else None
            c3, b3 = _post(a + "/hive/v12/verify_req/create", {"session_id": session_id, "ephemeral_salt": e_salt, "challenge": ch_a}, timeout=30)
            msg_a = b3.get("msg") if isinstance(b3, dict) else None
            c4, b4 = _post(e + "/hive/v12/verify_req/process", {"peer_id": a_id, "msg": msg_a, "ttl_s": float(args.ttl)}, timeout=30)
            eve["eve_process_a"] = {"create": {"code": c3, "body": b3}, "process": {"code": c4, "body": b4}}
        except Exception as exc:
            eve["error"] = str(exc)
        report["steps"]["eve_handshake_mismatch"] = eve

    # 1) baseline delivery
    msg1 = _send(a, b_id, args.message, pad_bytes=int(args.pad_bytes))
    report["steps"]["send_baseline"] = {
        "msg_sha256": _sha256_json(msg1),
        "payload_len": len(msg1.get("payload", [])) if isinstance(msg1.get("payload"), list) else None,
    }
    res1 = _receive(b, a_id, msg1)
    report["steps"]["recv_baseline"] = res1

    # 2) append-noise attack: should still deliver
    msg2 = _send(a, b_id, args.message + " [noise-test]", pad_bytes=int(args.pad_bytes))
    noisy = _append_noise(msg2, int(args.noise_bytes), rng)
    report["steps"]["intercept_append_noise"] = {
        "orig_payload_len": len(msg2.get("payload", [])) if isinstance(msg2.get("payload"), list) else None,
        "noisy_payload_len": len(noisy.get("payload", [])) if isinstance(noisy.get("payload"), list) else None,
        "msg_sha256": _sha256_json(noisy),
    }
    res2 = _receive(b, a_id, noisy)
    report["steps"]["recv_append_noise"] = res2

    # 3) in-band tamper: should be corrupt
    msg3 = _send(a, b_id, args.message + " [tamper-test]", pad_bytes=int(args.pad_bytes))
    tampered, meta = _flip_inband(msg3, rng)
    report["steps"]["intercept_flip_inband"] = {"meta": meta, "msg_sha256": _sha256_json(tampered)}
    res3 = _receive(b, a_id, tampered)
    report["steps"]["recv_flip_inband"] = res3

    # 3b) header tamper: should now be corrupt (AAD-bound MAC)
    msg3h = _send(a, b_id, args.message + " [hdr-tamper-test]", pad_bytes=int(args.pad_bytes))
    tampered_h = _tamper_header(msg3h, "dst_node_id", "EVE")
    report["steps"]["intercept_header_tamper"] = {"field": "dst_node_id", "new_value": "EVE", "msg_sha256": _sha256_json(tampered_h)}
    res3h = _receive(b, a_id, tampered_h)
    report["steps"]["recv_header_tamper"] = res3h

    # Optional: intercept and deliver to EVE (should not deliver; unknown_session expected).
    if e and e_id:
        try:
            er = _receive(e, a_id, msg1)
            report["steps"]["eve_receive_intercept"] = er
        except Exception as exc:
            report["steps"]["eve_receive_intercept"] = {"error": str(exc)}

    # 4) replay: baseline msg4 delivered, then replay rejected
    msg4 = _send(a, b_id, args.message + " [replay-test]", pad_bytes=int(args.pad_bytes))
    res4a = _receive(b, a_id, msg4)
    res4b = _receive(b, a_id, msg4)
    report["steps"]["recv_replay_first"] = res4a
    report["steps"]["recv_replay_second"] = res4b

    out_path = _write_log(report)

    print("A", a, "node_id=", a_id)
    print("B", b, "node_id=", b_id)
    if e and e_id:
        print("E", e, "node_id=", e_id)
    print("handshake", report["steps"]["handshake"]["a_to_b"]["process"].get("verified"), report["steps"]["handshake"]["b_to_a"]["process"].get("verified"))
    if e and e_id and "eve_handshake_mismatch" in report["steps"]:
        ehm = report["steps"]["eve_handshake_mismatch"]
        try:
            a_ok = bool(ehm["a_process_eve"]["process"]["body"].get("verified"))
            e_ok = bool(ehm["eve_process_a"]["process"]["body"].get("verified"))
            print("eve_handshake_verified", a_ok, e_ok)
        except Exception:
            pass
    print("baseline", res1.get("result"))
    print("append_noise", res2.get("result"))
    print("flip_inband", res3.get("result"))
    print("hdr_tamper", res3h.get("result"))
    print("replay_first", res4a.get("result"))
    print("replay_second", res4b.get("result"))
    print("WROTE", out_path)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
