#!/usr/bin/env python3
"""IDRE field-bound attack suite (HTTP black-box).

This attacks the node server endpoints:
  - /hive/v12/verify_req/*
  - /hive/v12/send
  - /hive/v12/receive

It does NOT attempt to recover plaintext. It validates that tamper/replay/header
mutation are detected and that wrong-field peers can't verify.
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


def _get(url: str, timeout: int = 20) -> Tuple[int, Dict[str, Any]]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception as read_exc:
            # Some servers abort large/error responses mid-flight; keep the suite running.
            body = f"<http_error_body_read_failed: {type(read_exc).__name__}: {read_exc}>"
        try:
            return exc.code, json.loads(body)
        except Exception:
            return exc.code, {"error": "http_error", "status": exc.code, "body": body}
    except urllib.error.URLError as exc:
        return 0, {"error": "url_error", "reason": str(exc)}
    except Exception as exc:
        return 0, {"error": "exception", "type": type(exc).__name__, "detail": str(exc)}


def _post(url: str, payload: Dict[str, Any], timeout: int = 60) -> Tuple[int, Dict[str, Any]]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception as read_exc:
            # Some servers abort large/error responses mid-flight; keep the suite running.
            body = f"<http_error_body_read_failed: {type(read_exc).__name__}: {read_exc}>"
        try:
            return exc.code, json.loads(body)
        except Exception:
            return exc.code, {"error": "http_error", "status": exc.code, "body": body}
    except urllib.error.URLError as exc:
        return 0, {"error": "url_error", "reason": str(exc)}
    except Exception as exc:
        return 0, {"error": "exception", "type": type(exc).__name__, "detail": str(exc)}

def _timed_post(url: str, payload: Dict[str, Any], timeout: int = 60) -> Dict[str, Any]:
    t0 = time.perf_counter()
    # Allow passing `{}` for GET-only endpoints when called mistakenly.
    # (Some checks log health via `_timed_post` for consistent schema.)
    if payload == {} and url.endswith("/health"):
        code, body = _get(url, timeout=timeout)
    else:
        code, body = _post(url, payload, timeout=timeout)
    dt_ms = (time.perf_counter() - t0) * 1000.0
    return {"code": code, "body": body, "latency_ms": dt_ms}


def _sha256_json(obj: Any) -> str:
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _write(report: Dict[str, Any]) -> str:
    os.makedirs("logs", exist_ok=True)
    out_path = os.path.join("logs", f"idre_http_attack_suite_{int(time.time())}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return out_path


def _hello(base: str) -> Dict[str, Any]:
    code, body = _post(base + "/hive/v12/hello", {}, timeout=10)
    if code != 200:
        raise RuntimeError(f"hello_failed {base}: {code} {body}")
    return body


def _handshake(a: str, a_id: str, b: str, b_id: str, session_id: str, e_salt: int, ttl_s: float) -> Dict[str, Any]:
    # a -> b
    cc1, cb1 = _post(b + "/hive/v12/challenge", {"peer_id": a_id}, timeout=30)
    ch1 = cb1.get("challenge") if isinstance(cb1, dict) else None
    c1, b1 = _post(
        a + "/hive/v12/verify_req/create",
        {"session_id": session_id, "ephemeral_salt": e_salt, "challenge": ch1},
        timeout=30,
    )
    msg1 = b1.get("msg") if isinstance(b1, dict) else None
    c2, b2 = _post(b + "/hive/v12/verify_req/process", {"peer_id": a_id, "msg": msg1, "ttl_s": ttl_s}, timeout=30)

    # b -> a
    cc3, cb3 = _post(a + "/hive/v12/challenge", {"peer_id": b_id}, timeout=30)
    ch2 = cb3.get("challenge") if isinstance(cb3, dict) else None
    c3, b3 = _post(
        b + "/hive/v12/verify_req/create",
        {"session_id": session_id, "ephemeral_salt": e_salt, "challenge": ch2},
        timeout=30,
    )
    msg2 = b3.get("msg") if isinstance(b3, dict) else None
    c4, b4 = _post(a + "/hive/v12/verify_req/process", {"peer_id": b_id, "msg": msg2, "ttl_s": ttl_s}, timeout=30)

    return {
        "a_to_b": {
            "challenge": {"code": cc1, "body": cb1},
            "create": {"code": c1},
            "process": {"code": c2, "body": b2},
        },
        "b_to_a": {
            "challenge": {"code": cc3, "body": cb3},
            "create": {"code": c3},
            "process": {"code": c4, "body": b4},
        },
    }


def _handshake_tamper(a: str, a_id: str, b: str, session_id: str, e_salt: int, ttl_s: float) -> Dict[str, Any]:
    """
    Attempts to tamper handshake headers while keeping payload unchanged.
    With a correctly bound VERIFY_REQ, these must be rejected (verified=false).
    """
    out: Dict[str, Any] = {}

    cc1, cb1 = _post(b + "/hive/v12/challenge", {"peer_id": a_id}, timeout=30)
    ch = cb1.get("challenge") if isinstance(cb1, dict) else None
    c1, b1 = _post(a + "/hive/v12/verify_req/create", {"session_id": session_id, "ephemeral_salt": e_salt, "challenge": ch}, timeout=30)
    msg = b1.get("msg") if isinstance(b1, dict) else None
    out["challenge"] = {"code": cc1, "body": cb1}
    out["create"] = {"code": c1}
    if not isinstance(msg, dict):
        out["error"] = "no_msg"
        return out

    # Tamper ephemeral_salt
    m1 = copy.deepcopy(msg)
    try:
        m1["ephemeral_salt"] = int(m1.get("ephemeral_salt", 0)) ^ 1
    except Exception:
        m1["ephemeral_salt"] = 1
    c2, b2 = _post(b + "/hive/v12/verify_req/process", {"peer_id": a_id, "msg": m1, "ttl_s": ttl_s}, timeout=30)
    out["tamper_ephemeral_salt"] = {"code": c2, "body": b2}

    # Tamper session_id (keep same length, mutate last nibble)
    m2 = copy.deepcopy(msg)
    sid = str(m2.get("session_id", ""))
    if sid:
        last = sid[-1]
        m2["session_id"] = sid[:-1] + ("0" if last != "0" else "1")
    else:
        m2["session_id"] = "0" * 32
    c3, b3 = _post(b + "/hive/v12/verify_req/process", {"peer_id": a_id, "msg": m2, "ttl_s": ttl_s}, timeout=30)
    out["tamper_session_id"] = {"code": c3, "body": b3}

    # Tamper field_profile_id (should be rejected)
    m3 = copy.deepcopy(msg)
    m3["field_profile_id"] = "deadbeefdeadbeef"
    c4, b4 = _post(b + "/hive/v12/verify_req/process", {"peer_id": a_id, "msg": m3, "ttl_s": ttl_s}, timeout=30)
    out["tamper_field_profile_id"] = {"code": c4, "body": b4}

    # Tamper challenge (should be rejected)
    m4 = copy.deepcopy(msg)
    m4["challenge"] = "00" * 16
    c5, b5 = _post(b + "/hive/v12/verify_req/process", {"peer_id": a_id, "msg": m4, "ttl_s": ttl_s}, timeout=30)
    out["tamper_challenge"] = {"code": c5, "body": b5}

    return out


def _send(a: str, dst_id: str, content: str, pad_bytes: int = 0) -> Dict[str, Any]:
    c, b = _post(a + "/hive/v12/send", {"dst_node_id": dst_id, "content": content, "pad_bytes": pad_bytes}, timeout=60)
    if c != 200:
        raise RuntimeError(f"send_failed {a}: {c} {b}")
    msg = b.get("msg")
    if not isinstance(msg, dict):
        raise RuntimeError(f"send_bad_msg {a}: {b}")
    return msg


def _send_with_time(
    a: str,
    dst_id: str,
    content: str,
    *,
    created_at_ms: int | None = None,
    expires_at_ms: int | None = None,
    expires_in_ms: int | None = None,
    pad_bytes: int = 0,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"dst_node_id": dst_id, "content": content, "pad_bytes": pad_bytes}
    if created_at_ms is not None:
        payload["created_at_ms"] = int(created_at_ms)
    if expires_at_ms is not None:
        payload["expires_at_ms"] = int(expires_at_ms)
    if expires_in_ms is not None:
        payload["expires_in_ms"] = int(expires_in_ms)
    c, b = _post(a + "/hive/v12/send", payload, timeout=60)
    if c != 200:
        raise RuntimeError(f"send_failed {a}: {c} {b}")
    msg = b.get("msg")
    if not isinstance(msg, dict):
        raise RuntimeError(f"send_bad_msg {a}: {b}")
    return msg


def _recv(b: str, prev_id: str, msg: Dict[str, Any]) -> Dict[str, Any]:
    res = _timed_post(b + "/hive/v12/receive", {"prev_hop_id": prev_id, "msg": msg}, timeout=60)
    if int(res["code"]) != 200:
        raise RuntimeError(f"recv_failed {b}: {res['code']} {res['body']}")
    return res["body"]


def _mutate_payload_append(msg: Dict[str, Any], n: int, rng: random.Random) -> Dict[str, Any]:
    out = copy.deepcopy(msg)
    p = out.get("payload")
    if isinstance(p, list) and n > 0:
        p.extend([rng.getrandbits(8) for _ in range(int(n))])
    return out


def _mutate_payload_truncate(msg: Dict[str, Any], n: int) -> Dict[str, Any]:
    out = copy.deepcopy(msg)
    p = out.get("payload")
    if isinstance(p, list) and n > 0 and len(p) > n:
        out["payload"] = p[: len(p) - int(n)]
    return out


def _mutate_payload_flip_inband(msg: Dict[str, Any], rng: random.Random) -> Dict[str, Any]:
    out = copy.deepcopy(msg)
    p = out.get("payload")
    if not isinstance(p, list) or not p:
        return out
    ct_len = int(p[0])
    start = 1
    end = min(1 + max(0, ct_len), len(p))
    if end <= start:
        return out
    idx = start + rng.randrange(end - start)
    out["payload"][idx] = (int(out["payload"][idx]) ^ 0x5A) & 0xFF
    return out


def _mutate_header(msg: Dict[str, Any], field: str, value: Any) -> Dict[str, Any]:
    out = copy.deepcopy(msg)
    out[field] = value
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--node-a", default="http://127.0.0.1:8890")
    ap.add_argument("--node-b", default="http://127.0.0.1:8891")
    ap.add_argument("--node-e", default="http://127.0.0.1:8892")
    ap.add_argument("--ttl", type=float, default=600.0)
    ap.add_argument("--pad-bytes", type=int, default=0)
    ap.add_argument("--noise-bytes", type=int, default=256)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument(
        "--slow",
        action="store_true",
        help="Run slow tests that require waiting (e.g., challenge expiry).",
    )
    args = ap.parse_args()

    a = args.node_a.rstrip("/")
    b = args.node_b.rstrip("/")
    e = args.node_e.rstrip("/")

    # health check + feature capture (proves we are hitting the updated server)
    report_health: Dict[str, Any] = {}
    for name, base in (("a", a), ("b", b), ("e", e)):
        hc, hb = _get(base + "/health", timeout=10)
        if hc != 200:
            # hc==0 means connect/timeout, hb contains the reason.
            raise RuntimeError(f"health_failed {base}: {hc} {hb}")
        feats = hb.get("features") if isinstance(hb, dict) else None
        if not (isinstance(feats, dict) and isinstance(feats.get("field_profile_id"), str) and feats["field_profile_id"]):
            raise RuntimeError(
                f"server_missing_field_profile_id {base}: restart nodes with updated scripts\\hive_v12_node_server.py"
            )
        report_health[name] = {"code": hc, "body": hb}

    hello_a = _hello(a)
    hello_b = _hello(b)
    hello_e = _hello(e)
    a_id = str(hello_a.get("node_id", "A"))
    b_id = str(hello_b.get("node_id", "B"))
    e_id = str(hello_e.get("node_id", "EVE"))

    rng = random.Random(int(args.seed))
    session_id = hashlib.sha256(f"{time.time()}:{rng.getrandbits(64)}".encode("utf-8")).hexdigest()[:32]
    e_salt = rng.getrandbits(31)

    report: Dict[str, Any] = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "nodes": {"a": a, "b": b, "e": e},
        "node_ids": {"a": a_id, "b": b_id, "e": e_id},
        "session_id": session_id,
        "ephemeral_salt": e_salt,
        "health": report_health,
        "steps": {},
    }

    # A<->B handshake should succeed
    report["steps"]["handshake_ab"] = _handshake(a, a_id, b, b_id, session_id, e_salt, float(args.ttl))

    # Handshake header tamper (should fail if VERIFY_REQ binds session_id + ephemeral_salt)
    report["steps"]["handshake_tamper_a_to_b"] = _handshake_tamper(a, a_id, b, session_id, e_salt, float(args.ttl))
    report["steps"]["handshake_tamper_b_to_a"] = _handshake_tamper(b, b_id, a, session_id, e_salt, float(args.ttl))

    # EVE mismatch: E->A and A->E should fail verify (verified=false)
    eve_mismatch: Dict[str, Any] = {}
    cc1, cb1 = _post(a + "/hive/v12/challenge", {"peer_id": e_id}, timeout=30)
    ch_e = cb1.get("challenge") if isinstance(cb1, dict) else None
    c1, b1 = _post(e + "/hive/v12/verify_req/create", {"session_id": session_id, "ephemeral_salt": e_salt, "challenge": ch_e}, timeout=30)
    msg_e = b1.get("msg") if isinstance(b1, dict) else None
    c2, b2 = _post(a + "/hive/v12/verify_req/process", {"peer_id": e_id, "msg": msg_e, "ttl_s": float(args.ttl)}, timeout=30)
    eve_mismatch["e_to_a"] = {"challenge": {"code": cc1, "body": cb1}, "create": {"code": c1}, "process": {"code": c2, "body": b2}}

    cc3, cb3 = _post(e + "/hive/v12/challenge", {"peer_id": a_id}, timeout=30)
    ch_a = cb3.get("challenge") if isinstance(cb3, dict) else None
    c3, b3 = _post(a + "/hive/v12/verify_req/create", {"session_id": session_id, "ephemeral_salt": e_salt, "challenge": ch_a}, timeout=30)
    msg_a = b3.get("msg") if isinstance(b3, dict) else None
    c4, b4 = _post(e + "/hive/v12/verify_req/process", {"peer_id": a_id, "msg": msg_a, "ttl_s": float(args.ttl)}, timeout=30)
    eve_mismatch["a_to_e"] = {"challenge": {"code": cc3, "body": cb3}, "create": {"code": c3}, "process": {"code": c4, "body": b4}}
    report["steps"]["handshake_eve_mismatch"] = eve_mismatch

    # Baseline message (deliver)
    msg = _send(a, b_id, "attack-suite baseline", pad_bytes=int(args.pad_bytes))
    report["steps"]["baseline_send"] = {"sha256": _sha256_json(msg), "payload_len": len(msg.get("payload", []))}
    report["steps"]["baseline_recv"] = _recv(b, a_id, msg)

    # Replay (reject)
    report["steps"]["replay_1"] = _recv(b, a_id, msg)
    report["steps"]["replay_2"] = _recv(b, a_id, msg)

    # Append noise (should deliver)
    msg2 = _send(a, b_id, "attack-suite append-noise", pad_bytes=int(args.pad_bytes))
    noisy = _mutate_payload_append(msg2, int(args.noise_bytes), rng)
    report["steps"]["append_noise"] = {"orig_len": len(msg2.get("payload", [])), "noisy_len": len(noisy.get("payload", []))}
    report["steps"]["append_noise_recv"] = _recv(b, a_id, noisy)

    # Truncate (corrupt)
    msg3 = _send(a, b_id, "attack-suite truncate", pad_bytes=int(args.pad_bytes))
    trunc = _mutate_payload_truncate(msg3, 10)
    report["steps"]["truncate_recv"] = _recv(b, a_id, trunc)

    # Flip in-band (corrupt)
    msg4 = _send(a, b_id, "attack-suite flip-inband", pad_bytes=int(args.pad_bytes))
    flip = _mutate_payload_flip_inband(msg4, rng)
    report["steps"]["flip_inband_recv"] = _recv(b, a_id, flip)

    # ct_len tamper (too small -> tag read from wrong offset => corrupt)
    msg4b = _send(a, b_id, "attack-suite ctlen=0", pad_bytes=int(args.pad_bytes))
    ct0 = copy.deepcopy(msg4b)
    if isinstance(ct0.get("payload"), list) and ct0["payload"]:
        ct0["payload"][0] = 0
    report["steps"]["ctlen_zero_recv"] = _recv(b, a_id, ct0)

    # Tag strip (missing tag => corrupt)
    msg4c = _send(a, b_id, "attack-suite tag-strip", pad_bytes=int(args.pad_bytes))
    strip = copy.deepcopy(msg4c)
    p = strip.get("payload")
    if isinstance(p, list) and len(p) > 33:
        strip["payload"] = p[:-32]
    report["steps"]["tag_strip_recv"] = _recv(b, a_id, strip)

    # Header tamper: dst_node_id (should corrupt with AAD-bound MAC)
    msg5 = _send(a, b_id, "attack-suite header-tamper", pad_bytes=int(args.pad_bytes))
    hdr = _mutate_header(msg5, "dst_node_id", "EVE")
    report["steps"]["header_tamper_dst_recv"] = _recv(b, a_id, hdr)

    # Header tamper: field_profile_id (should reject early as wrong_profile)
    msg5a = _send(a, b_id, "attack-suite profile-id-tamper", pad_bytes=int(args.pad_bytes))
    hdr2 = _mutate_header(msg5a, "field_profile_id", "deadbeefdeadbeef")
    report["steps"]["header_tamper_profile_id_recv"] = _recv(b, a_id, hdr2)

    # Type confusion: payload is string (bad_payload expected)
    msg5b = _send(a, b_id, "attack-suite payload-type", pad_bytes=int(args.pad_bytes))
    tc = copy.deepcopy(msg5b)
    tc["payload"] = "not-a-list"
    report["steps"]["payload_type_confusion_recv"] = _recv(b, a_id, tc)

    # Prev-hop spoof (unknown_session)
    msg6 = _send(a, b_id, "attack-suite prevhop-spoof", pad_bytes=int(args.pad_bytes))
    report["steps"]["prevhop_spoof_recv"] = _recv(b, "NOT_A", msg6)

    # Intercept to EVE (should not deliver; expect reject)
    report["steps"]["deliver_to_eve_recv"] = _recv(e, a_id, msg6)

    # Oversize probe: keep HTTP body under DEFAULT_MAX_BODY_BYTES but exceed DEFAULT_MAX_PAYLOAD_INTS.
    # This should return a clean 413 from /receive without triggering early connection abort.
    huge = {"prev_hop_id": a_id, "msg": {"type": "DATA", "payload": [0] * 250000}}
    report["steps"]["oversize_payload_probe"] = _timed_post(b + "/hive/v12/receive", huge, timeout=60)
    report["steps"]["health_after_oversize"] = {"b": _timed_post(b + "/health", {}, timeout=10)}

    # Handshake replay: reuse an already-processed VERIFY_REQ should fail (challenge is one-time).
    hr: Dict[str, Any] = {}
    ccx, cbx = _post(b + "/hive/v12/challenge", {"peer_id": a_id}, timeout=30)
    chx = cbx.get("challenge") if isinstance(cbx, dict) else None
    ccr, br = _post(a + "/hive/v12/verify_req/create", {"session_id": session_id, "ephemeral_salt": e_salt, "challenge": chx}, timeout=30)
    msg_r = br.get("msg") if isinstance(br, dict) else None
    cpa1, bpa1 = _post(b + "/hive/v12/verify_req/process", {"peer_id": a_id, "msg": msg_r, "ttl_s": float(args.ttl)}, timeout=30)
    cpa2, bpa2 = _post(b + "/hive/v12/verify_req/process", {"peer_id": a_id, "msg": msg_r, "ttl_s": float(args.ttl)}, timeout=30)
    hr["challenge"] = {"code": ccx, "body": cbx}
    hr["create"] = {"code": ccr}
    hr["process_1"] = {"code": cpa1, "body": bpa1}
    hr["process_2"] = {"code": cpa2, "body": bpa2}
    report["steps"]["handshake_replay_verify_req"] = hr

    # Handshake challenge must be bound to peer_id; processing with the wrong peer_id should fail.
    pm: Dict[str, Any] = {}
    ccp, cbp = _post(b + "/hive/v12/challenge", {"peer_id": a_id}, timeout=30)
    chp = cbp.get("challenge") if isinstance(cbp, dict) else None
    ccrp, brp = _post(
        a + "/hive/v12/verify_req/create",
        {"session_id": session_id, "ephemeral_salt": e_salt, "challenge": chp},
        timeout=30,
    )
    msg_p = brp.get("msg") if isinstance(brp, dict) else None
    cpp, bpp = _post(
        b + "/hive/v12/verify_req/process",
        {"peer_id": b_id, "msg": msg_p, "ttl_s": float(args.ttl)},
        timeout=30,
    )
    pm["challenge"] = {"code": ccp, "body": cbp}
    pm["create"] = {"code": ccrp}
    pm["process_wrong_peer_id"] = {"code": cpp, "body": bpp}
    report["steps"]["handshake_peer_id_mismatch"] = pm

    # Challenge expiry: a stale VERIFY_REQ should fail after challenge TTL (slow, optional).
    if bool(args.slow):
        ex: Dict[str, Any] = {}
        cce, cbe = _post(b + "/hive/v12/challenge", {"peer_id": a_id}, timeout=30)
        che = cbe.get("challenge") if isinstance(cbe, dict) else None
        exp_ms = cbe.get("expires_at_ms") if isinstance(cbe, dict) else None
        ccre, bre = _post(
            a + "/hive/v12/verify_req/create",
            {"session_id": session_id, "ephemeral_salt": e_salt, "challenge": che},
            timeout=30,
        )
        msg_e = bre.get("msg") if isinstance(bre, dict) else None

        sleep_s = 0.0
        if isinstance(exp_ms, int):
            now_ms = int(time.time() * 1000.0)
            sleep_s = max(0.0, (exp_ms - now_ms + 50) / 1000.0)
        time.sleep(sleep_s)

        cpe, bpe = _post(
            b + "/hive/v12/verify_req/process",
            {"peer_id": a_id, "msg": msg_e, "ttl_s": float(args.ttl)},
            timeout=30,
        )
        ex["challenge"] = {"code": cce, "body": cbe}
        ex["create"] = {"code": ccre}
        ex["slept_s"] = sleep_s
        ex["process_after_expiry"] = {"code": cpe, "body": bpe}
        report["steps"]["handshake_challenge_expiry"] = ex

    # Time enforcement (requires server to MAC timestamps into AAD)
    now_ms = int(time.time() * 1000.0)
    expired_msg = _send_with_time(a, b_id, "attack-suite expired", created_at_ms=now_ms - 120000, expires_at_ms=now_ms - 60000, pad_bytes=int(args.pad_bytes))
    report["steps"]["expired_recv"] = _recv(b, a_id, expired_msg)

    future_msg = _send_with_time(a, b_id, "attack-suite future", created_at_ms=now_ms + 300000, expires_in_ms=60000, pad_bytes=int(args.pad_bytes))
    report["steps"]["clock_skew_recv"] = _recv(b, a_id, future_msg)

    longttl_msg = _send_with_time(a, b_id, "attack-suite ttl-too-long", created_at_ms=now_ms, expires_in_ms=601000, pad_bytes=int(args.pad_bytes))
    report["steps"]["ttl_too_long_recv"] = _recv(b, a_id, longttl_msg)

    # Session TTL expiry (slow, optional): establish a short-lived session and ensure it cannot be used after expiry.
    # Note: this will replace the existing A<->B session for the duration of the suite (by peer_id),
    # so keep it opt-in.
    if bool(args.slow):
        st: Dict[str, Any] = {}
        sid2 = hashlib.sha256(f"ttl-expiry:{time.time()}:{rng.getrandbits(64)}".encode("utf-8")).hexdigest()[:32]
        salt2 = rng.getrandbits(31)
        st["session_id"] = sid2
        st["ephemeral_salt"] = salt2
        st["handshake"] = _handshake(a, a_id, b, b_id, sid2, salt2, ttl_s=1.0)

        # Should work immediately.
        try:
            m_now = _send(a, b_id, "attack-suite ttl-expiry immediate", pad_bytes=int(args.pad_bytes))
            st["send_immediate"] = {"ok": True}
            st["recv_immediate"] = _recv(b, a_id, m_now)
        except Exception as exc:
            st["send_immediate"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

        time.sleep(2.0)
        # After expiry, sender or receiver should refuse (unknown_session).
        try:
            m_late = _send(a, b_id, "attack-suite ttl-expiry late", pad_bytes=int(args.pad_bytes))
            st["send_after_expiry"] = {"ok": True}
            st["recv_after_expiry"] = _recv(b, a_id, m_late)
        except Exception as exc:
            st["send_after_expiry"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

        report["steps"]["session_ttl_expiry"] = st

    out_path = _write(report)
    print("WROTE", out_path)
    print("baseline", report["steps"]["baseline_recv"].get("result"))
    print("append_noise", report["steps"]["append_noise_recv"].get("result"))
    print("flip_inband", report["steps"]["flip_inband_recv"].get("result"))
    print("hdr_tamper", report["steps"]["header_tamper_dst_recv"].get("result"))
    print("replay_2", report["steps"]["replay_2"].get("result"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
