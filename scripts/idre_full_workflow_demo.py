#!/usr/bin/env python3
"""Full IDRE workflow demo with targeted tamper modes.

Flow:
1) Node A encodes an "encrypted" pointer packet via /api/idre/send.
2) We "intercept" the packet on the wire (packet_b64).
3) Attacker attempts:
   - decode with missing trust_store (should fail)
   - decode with wrong key (auth_fail)
   - tamper packet bytes (noise injection) then decode with correct key (expected auth_fail)
4) Legit receiver on Node B decodes original packet successfully.
5) Replay of same packet is rejected (replay_fail).

Tamper modes:
- header: flip a byte in the header section
- pointers: flip a byte in the pointer payload section
- signature: flip a byte in the signature section

This demo does NOT use /v1/local/reflex. It only exercises IDRE endpoints.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
from typing import Any

sys.dont_write_bytecode = True

# Wire format constants (must match idre-protocol/idre/wire.py)
HEADER_LEN = 1 + 1 + 16 + 16 + 8 + 8 + 32  # >BB16s16sQQ32s
POINTERS_LEN = 256
SIG_LEN = 64
WIRE_SIZE = HEADER_LEN + POINTERS_LEN + SIG_LEN

def _post(url: str, payload: dict[str, Any], timeout: int = 120) -> tuple[int, dict[str, Any]]:
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

def _pack_message(msg: str) -> list[int]:
    b = msg.encode("utf-8")
    if len(b) > 254:
        raise ValueError(f"message too long: {len(b)} bytes (max 254)")
    out = bytearray(256)
    out[0] = (len(b) >> 8) & 0xFF
    out[1] = len(b) & 0xFF
    out[2 : 2 + len(b)] = b
    return [x for x in out]

def _unpack_message(indices: list[int]) -> str:
    if len(indices) != 256:
        raise ValueError("decoded_indices must be 256")
    n = ((indices[0] & 0xFF) << 8) | (indices[1] & 0xFF)
    raw = bytes((x & 0xFF) for x in indices[2 : 2 + n])
    return raw.decode("utf-8", errors="replace")

def _rand_hex(rng: random.Random, n: int) -> str:
    return bytes(rng.getrandbits(8) for _ in range(n)).hex()

def _flip_byte(buf: bytearray, idx: int, mask: int = 0x5A) -> dict[str, Any]:
    before = buf[idx]
    buf[idx] ^= mask
    after = buf[idx]
    return {"index": idx, "before": before, "after": after, "xor": mask}

def _tamper(packet_bytes: bytes, mode: str, rng: random.Random) -> tuple[bytes, dict[str, Any]]:
    if len(packet_bytes) != WIRE_SIZE:
        # still allow tamper, but report
        meta = {"warning": f"unexpected wire size {len(packet_bytes)} (expected {WIRE_SIZE})"}
    else:
        meta = {}

    b = bytearray(packet_bytes)
    if mode == "header":
        start, end = 0, min(HEADER_LEN, len(b))
    elif mode == "pointers":
        start, end = min(HEADER_LEN, len(b)), min(HEADER_LEN + POINTERS_LEN, len(b))
    elif mode == "signature":
        start, end = max(0, len(b) - SIG_LEN), len(b)
    else:
        raise ValueError(f"unknown tamper mode: {mode}")

    if end - start <= 0:
        idx = 0
    else:
        idx = start + rng.randrange(end - start)

    meta.update({"mode": mode, "range": [start, end]})
    meta.update(_flip_byte(b, idx))
    return bytes(b), meta

def _write(report: dict[str, Any]) -> str:
    os.makedirs("logs", exist_ok=True)
    out_path = os.path.join("logs", f"idre_full_workflow_{int(time.time())}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return out_path

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--node-a", default="http://127.0.0.1:8870")
    ap.add_argument("--node-b", default="http://127.0.0.1:8871")
    ap.add_argument("--message", default="Meet at 0300Z. Contract TV0001.")
    ap.add_argument("--counter", type=int, default=0, help="0 = auto")
    ap.add_argument("--seed", type=int, default=1337, help="Deterministic seed for ids + tamper")
    ap.add_argument("--tamper-mode", choices=["header", "pointers", "signature"], default="pointers")
    args = ap.parse_args()

    node_a = args.node_a.rstrip("/")
    node_b = args.node_b.rstrip("/")

    rng = random.Random(args.seed)
    session_id_hex = _rand_hex(rng, 16)
    sender_id_hex = _rand_hex(rng, 16)
    counter = int(args.counter) if int(args.counter) > 0 else int(time.time())

    state = {
        "seed": 7245,
        "plane_id": "covenant",
        "tau": 0.7,
        "epoch": 2,
        "state_digest": hashlib.sha256(b"demo-field-state").hexdigest(),
    }

    semantic_indices = _pack_message(args.message)

    report: dict[str, Any] = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "node_a": node_a,
        "node_b": node_b,
        "message": args.message,
        "state": state,
        "session_id_hex": session_id_hex,
        "sender_id_hex": sender_id_hex,
        "counter": counter,
        "tamper_mode": args.tamper_mode,
        "steps": {},
    }

    # 1) SEND
    sc, sb = _post(
        node_a + "/api/idre/send",
        {
            "state": state,
            "semantic_indices": semantic_indices,
            "encode_ctx": {
                "session_id": session_id_hex,
                "sender_id": sender_id_hex,
                "counter": counter,
                "private_key_seed": "alice",
            },
        },
    )
    report["steps"]["send"] = {"code": sc, "body": sb}
    if sc != 200 or sb.get("status") != "ok":
        print("SEND failed", sc, sb)
        print("WROTE", _write(report))
        return 2

    packet_b64 = sb.get("packet_b64", "")
    pub_hex = sb.get("public_key_hex", "")
    packet_bytes = base64.b64decode(packet_b64.encode("ascii"))

    report["steps"]["intercept"] = {
        "packet_len": len(packet_bytes),
        "packet_sha256": hashlib.sha256(packet_bytes).hexdigest(),
        "packet_b64_prefix": packet_b64[:100] + "...",
    }

    # 2) ATTACK: missing trust_store
    mc, mb = _post(node_b + "/api/idre/receive", {"state": state, "packet_b64": packet_b64, "decode_ctx": {}})
    report["steps"]["attack_missing_trust"] = {"code": mc, "body": mb}

    # 3) ATTACK: wrong key
    wrong_key = "11" * 32
    wc, wb = _post(
        node_b + "/api/idre/receive",
        {
            "state": state,
            "packet_b64": packet_b64,
            "decode_ctx": {
                "trust_store": {sender_id_hex: wrong_key},
                "expected_session_id": session_id_hex,
                "expected_sender_id": sender_id_hex,
            },
        },
    )
    report["steps"]["attack_wrong_key"] = {"code": wc, "body": wb}

    # 4) NOISE INJECTION (tamper packet) then decode with correct key
    tampered_bytes, tamper_meta = _tamper(packet_bytes, args.tamper_mode, rng)
    tampered_b64 = base64.b64encode(tampered_bytes).decode("ascii")
    tc, tb = _post(
        node_b + "/api/idre/receive",
        {
            "state": state,
            "packet_b64": tampered_b64,
            "decode_ctx": {
                "trust_store": {sender_id_hex: pub_hex},
                "expected_session_id": session_id_hex,
                "expected_sender_id": sender_id_hex,
                "expected_indices": semantic_indices,
            },
        },
    )
    report["steps"]["tamper"] = {
        "meta": tamper_meta,
        "tampered_sha256": hashlib.sha256(tampered_bytes).hexdigest(),
        "receive": {"code": tc, "body": tb},
    }

    # 5) LEGIT decode on Node B
    rc, rb = _post(
        node_b + "/api/idre/receive",
        {
            "state": state,
            "packet_b64": packet_b64,
            "decode_ctx": {
                "trust_store": {sender_id_hex: pub_hex},
                "expected_session_id": session_id_hex,
                "expected_sender_id": sender_id_hex,
                "expected_indices": semantic_indices,
            },
        },
    )
    decrypted = None
    if isinstance(rb, dict) and rb.get("decode_status") == "ok":
        decrypted = _unpack_message(rb.get("decoded_indices", [0] * 256))
    report["steps"]["receive_ok"] = {"code": rc, "body": rb, "decrypted_message": decrypted}

    # 6) Replay should fail
    r2c, r2b = _post(
        node_b + "/api/idre/receive",
        {
            "state": state,
            "packet_b64": packet_b64,
            "decode_ctx": {
                "trust_store": {sender_id_hex: pub_hex},
                "expected_session_id": session_id_hex,
                "expected_sender_id": sender_id_hex,
                "expected_indices": semantic_indices,
            },
        },
    )
    report["steps"]["replay"] = {"code": r2c, "body": r2b}

    print("SEND", sc, "ok")
    print("INTERCEPT sha256", report["steps"]["intercept"]["packet_sha256"])
    print("ATTACK missing_trust", mb.get("error") if isinstance(mb, dict) else "-")
    print("ATTACK wrong_key", wb.get("decode_status") if isinstance(wb, dict) else "-")
    print("TAMPER(" + args.tamper_mode + ")", tb.get("decode_status") if isinstance(tb, dict) else "-")
    print("RECEIVE ok", rb.get("decode_status") if isinstance(rb, dict) else "-")
    print("DECRYPTED", decrypted)
    print("REPLAY", r2b.get("decode_status") if isinstance(r2b, dict) else "-")

    out_path = _write(report)
    print("WROTE", out_path)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
