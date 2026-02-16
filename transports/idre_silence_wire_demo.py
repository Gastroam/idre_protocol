#!/usr/bin/env python3
"""Cross-node demo: carry an IDRE/Hive v1.2 message over IDRE-Silence audio.

Flow:
1. Handshake A <-> B (same field required).
2. Ask node A to build an encrypted message to node B (/hive/v12/send).
3. Pack the resulting wire message into compact bytes.
4. Encode bytes -> audio WAV (IDRE-Silence).
5. EVE "intercepts" the WAV:
   - can decode transport bytes, but only sees integer payload (no plaintext)
   - cannot establish a session with A if wrong-field
   - replay/tamper attempts against B are rejected
6. Node B decodes WAV -> bytes -> wire msg -> /hive/v12/receive.

This is transport-only. IDRE security remains in the Hive message.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Tuple


# Allow running as a script without installing the package.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from idre_clean.transports.idre_silence import IDRESilenceProtocol
from idre_clean.transports.wav_io import read_wav_pcm16, write_wav_pcm16


MAGIC = b"IDRW1"


def _now_ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _sha256(x: bytes) -> str:
    return hashlib.sha256(x).hexdigest()


def _get(url: str, timeout: int = 10) -> Tuple[int, Dict[str, Any]]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception as read_exc:
            body = f"<http_error_body_read_failed: {type(read_exc).__name__}: {read_exc}>"
        try:
            return exc.code, json.loads(body)
        except Exception:
            return exc.code, {"error": "http_error", "status": exc.code, "body": body}
    except Exception as exc:
        return 0, {"error": "exception", "type": type(exc).__name__, "detail": str(exc)}


def _post(url: str, payload: Dict[str, Any], timeout: int = 30) -> Tuple[int, Dict[str, Any]]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception as read_exc:
            body = f"<http_error_body_read_failed: {type(read_exc).__name__}: {read_exc}>"
        try:
            return exc.code, json.loads(body)
        except Exception:
            return exc.code, {"error": "http_error", "status": exc.code, "body": body}
    except Exception as exc:
        return 0, {"error": "exception", "type": type(exc).__name__, "detail": str(exc)}


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
        a + "/hive/v12/verify_req/create", {"session_id": session_id, "ephemeral_salt": e_salt, "challenge": ch1}, timeout=30
    )
    msg1 = b1.get("msg") if isinstance(b1, dict) else None
    c2, b2 = _post(b + "/hive/v12/verify_req/process", {"peer_id": a_id, "msg": msg1, "ttl_s": ttl_s}, timeout=30)

    # b -> a
    cc3, cb3 = _post(a + "/hive/v12/challenge", {"peer_id": b_id}, timeout=30)
    ch2 = cb3.get("challenge") if isinstance(cb3, dict) else None
    c3, b3 = _post(
        b + "/hive/v12/verify_req/create", {"session_id": session_id, "ephemeral_salt": e_salt, "challenge": ch2}, timeout=30
    )
    msg2 = b3.get("msg") if isinstance(b3, dict) else None
    c4, b4 = _post(a + "/hive/v12/verify_req/process", {"peer_id": b_id, "msg": msg2, "ttl_s": ttl_s}, timeout=30)

    return {
        "a_to_b": {"challenge": {"code": cc1, "body": cb1}, "create": {"code": c1}, "process": {"code": c2, "body": b2}},
        "b_to_a": {"challenge": {"code": cc3, "body": cb3}, "create": {"code": c3}, "process": {"code": c4, "body": b4}},
    }


def _encode_str(s: str) -> bytes:
    b = (s or "").encode("utf-8")
    if len(b) > 255:
        raise ValueError("string_too_long")
    return bytes([len(b)]) + b


def _decode_str(buf: bytes, off: int) -> Tuple[str, int]:
    if off >= len(buf):
        raise ValueError("trunc")
    n = int(buf[off])
    off += 1
    if off + n > len(buf):
        raise ValueError("trunc")
    s = buf[off : off + n].decode("utf-8", errors="strict")
    return s, off + n


def pack_hive_receive_envelope(prev_hop_id: str, msg: Dict[str, Any]) -> bytes:
    """Pack the minimum data needed to call /hive/v12/receive."""
    payload = msg.get("payload")
    if not isinstance(payload, list):
        raise ValueError("bad_msg_payload")

    # Header fields (outer msg)
    m_type = str(msg.get("type", "DATA"))
    session_id = str(msg.get("session_id", ""))
    nonce = int(msg.get("nonce", 0))
    src = str(msg.get("src_node_id", ""))
    dst = str(msg.get("dst_node_id", ""))
    hop = int(msg.get("hop_count", 0))
    max_hops = int(msg.get("max_hops", 8))

    # Payload list is: [ct_len(int)][ct_bytes...][tag(32 bytes)][noise...]
    if not payload:
        raise ValueError("empty_payload")
    ct_len = int(payload[0])
    if ct_len < 0:
        raise ValueError("bad_ct_len")
    ct = bytes(int(x) & 0xFF for x in payload[1 : 1 + ct_len])
    tag = bytes(int(x) & 0xFF for x in payload[1 + ct_len : 1 + ct_len + 32])
    pad = bytes(int(x) & 0xFF for x in payload[1 + ct_len + 32 :])
    if len(tag) != 32:
        raise ValueError("bad_tag")

    out = bytearray()
    out.extend(MAGIC)
    out.extend(_encode_str(prev_hop_id))
    out.extend(_encode_str(m_type))
    out.extend(_encode_str(session_id))
    out.extend(nonce.to_bytes(8, "big", signed=False))
    out.extend(_encode_str(src))
    out.extend(_encode_str(dst))
    out.extend(bytes([hop & 0xFF, max_hops & 0xFF]))
    out.extend(int(ct_len).to_bytes(4, "big", signed=False))
    out.extend(ct)
    out.extend(tag)
    out.extend(len(pad).to_bytes(4, "big", signed=False))
    out.extend(pad)
    return bytes(out)


def unpack_hive_receive_envelope(blob: bytes) -> Tuple[str, Dict[str, Any]]:
    if not blob.startswith(MAGIC):
        raise ValueError("bad_magic")
    off = len(MAGIC)
    prev, off = _decode_str(blob, off)
    m_type, off = _decode_str(blob, off)
    session_id, off = _decode_str(blob, off)
    if off + 8 > len(blob):
        raise ValueError("trunc")
    nonce = int.from_bytes(blob[off : off + 8], "big", signed=False)
    off += 8
    src, off = _decode_str(blob, off)
    dst, off = _decode_str(blob, off)
    if off + 2 > len(blob):
        raise ValueError("trunc")
    hop = int(blob[off])
    max_hops = int(blob[off + 1])
    off += 2
    if off + 4 > len(blob):
        raise ValueError("trunc")
    ct_len = int.from_bytes(blob[off : off + 4], "big", signed=False)
    off += 4
    if off + ct_len + 32 + 4 > len(blob):
        raise ValueError("trunc")
    ct = blob[off : off + ct_len]
    off += ct_len
    tag = blob[off : off + 32]
    off += 32
    pad_len = int.from_bytes(blob[off : off + 4], "big", signed=False)
    off += 4
    if off + pad_len > len(blob):
        raise ValueError("trunc")
    pad = blob[off : off + pad_len]

    payload_list = [int(ct_len)] + [b for b in ct] + [b for b in tag] + [b for b in pad]
    msg = {
        "type": m_type,
        "session_id": session_id,
        "nonce": int(nonce),
        "src_node_id": src,
        "dst_node_id": dst,
        "hop_count": int(hop),
        "max_hops": int(max_hops),
        "payload": payload_list,
    }
    return prev, msg


def _maybe_play_wav(path: str) -> None:
    try:
        import winsound

        winsound.PlaySound(path, winsound.SND_FILENAME)
    except Exception:
        # Keep demo dependency-free.
        return


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--node-a", type=str, default="http://127.0.0.1:8890")
    ap.add_argument("--node-b", type=str, default="http://127.0.0.1:8891")
    ap.add_argument("--node-e", type=str, default="http://127.0.0.1:8892")
    ap.add_argument("--message-file", type=str, default="")
    ap.add_argument("--message", type=str, default="")
    ap.add_argument("--pad-bytes", type=int, default=0)
    ap.add_argument("--fec-repeat", type=int, default=3)
    ap.add_argument("--amplitude", type=float, default=0.5)
    ap.add_argument("--sr", type=int, default=44100)
    ap.add_argument("--out-wav", type=str, default="")
    ap.add_argument("--play-a", action="store_true", help="Play the encoded WAV on this machine.")
    ap.add_argument("--play-b", action="store_true", help="Play the received WAV on this machine (same file).")
    args = ap.parse_args()

    a = str(args.node_a).rstrip("/")
    b = str(args.node_b).rstrip("/")
    e = str(args.node_e).rstrip("/")

    hello_a = _hello(a)
    hello_b = _hello(b)
    hello_e = _hello(e)
    a_id = str(hello_a.get("node_id", "A"))
    b_id = str(hello_b.get("node_id", "B"))
    e_id = str(hello_e.get("node_id", "EVE"))

    session_id = secrets.token_hex(16)
    eph = 1145179090

    report: Dict[str, Any] = {
        "ts": _now_ts(),
        "nodes": {"a": a, "b": b, "e": e},
        "node_ids": {"a": a_id, "b": b_id, "e": e_id},
        "session_id": session_id,
        "ephemeral_salt": int(eph),
        "steps": {},
    }

    # Handshake A<->B
    report["steps"]["handshake_ab"] = _handshake(a, a_id, b, b_id, session_id, eph, ttl_s=600.0)

    # Wrong-field EVE handshake attempts (expected false)
    report["steps"]["handshake_eve_mismatch"] = {
        "e_to_a": _handshake(e, e_id, a, a_id, session_id, eph, ttl_s=600.0),
        "e_to_b": _handshake(e, e_id, b, b_id, session_id, eph, ttl_s=600.0),
    }

    # Load long message
    if args.message_file:
        raw = Path(str(args.message_file)).read_bytes()
        content = raw.decode("utf-8", errors="replace")
    else:
        content = str(args.message) if args.message else (
            "OFFLINE IDRE-SILENCE DEMO\n\n"
            "This is a longer letter/report payload used to test offline audio transport.\n"
            "It should arrive at B intact; EVE should only see semantic-free integers.\n\n"
            "Regards,\n"
            "IDRE\n"
        )

    # Ask A to build encrypted msg to B (normal online send)
    c_send, b_send = _post(a + "/hive/v12/send", {"dst_node_id": b_id, "content": content, "pad_bytes": int(args.pad_bytes)}, timeout=60)
    msg = (b_send.get("msg") if isinstance(b_send, dict) else None) if c_send == 200 else None
    if not isinstance(msg, dict):
        report["steps"]["send"] = {"code": c_send, "body": b_send}
        out = os.path.join("logs", f"idre_silence_wire_demo_{int(time.time())}.json")
        os.makedirs("logs", exist_ok=True)
        Path(out).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"WROTE {out}")
        return 2

    report["steps"]["send"] = {
        "code": c_send,
        "payload_len_ints": int(len(msg.get("payload", []))) if isinstance(msg.get("payload"), list) else None,
        "nonce": int(msg.get("nonce", 0)),
    }

    # Pack to compact bytes, then to audio.
    blob = pack_hive_receive_envelope(prev_hop_id=a_id, msg=msg)
    report["steps"]["pack"] = {"bytes": int(len(blob)), "sha256": _sha256(blob)}

    codec = IDRESilenceProtocol(sample_rate=int(args.sr), fec_repeat=int(args.fec_repeat))
    audio = codec.encode_bytes(blob, carrier_amplitude=float(args.amplitude))
    out_wav = str(args.out_wav) if args.out_wav else os.path.join("logs", f"idre_wire_{a_id}_to_{b_id}_{int(time.time())}.wav")
    write_wav_pcm16(out_wav, int(codec.sr), audio)
    report["steps"]["encode_audio"] = {"wav": out_wav, "samples": int(audio.size), "sr": int(codec.sr)}
    print(f"[A] wrote audio carrier: {out_wav}")
    if bool(args.play_a):
        _maybe_play_wav(out_wav)

    # EVE intercepts: can decode bytes, but can't use them to decrypt.
    sr_r, x = read_wav_pcm16(out_wav)
    dec = codec.decode_bytes(x)
    report["steps"]["eve_intercept_decode"] = {"ok": bool(dec is not None), "sr": int(sr_r)}
    if dec is None:
        report["steps"]["eve_intercept_decode"]["error"] = "decode_failed"
    else:
        # EVE sees msg envelope (still semantic-free ints).
        try:
            prev2, msg2 = unpack_hive_receive_envelope(dec)
            report["steps"]["eve_intercept_peek"] = {
                "prev_hop_id": prev2,
                "msg_keys": sorted(list(msg2.keys())),
                "payload_ints": int(len(msg2.get("payload", []))) if isinstance(msg2.get("payload"), list) else None,
                "note": "payload is integers (no plaintext)",
            }
        except Exception as exc:
            report["steps"]["eve_intercept_peek"] = {"error": type(exc).__name__, "detail": str(exc)}

        # EVE tries to submit to its own /receive (expected unknown_session)
        c_eve, b_eve = _post(e + "/hive/v12/receive", {"prev_hop_id": a_id, "msg": msg}, timeout=30)
        report["steps"]["eve_receive_attempt"] = {"code": c_eve, "body": b_eve}

    # B receives: decode and post to /receive
    dec2 = codec.decode_bytes(x)
    if dec2 is None:
        report["steps"]["b_decode"] = {"ok": False}
        return 3
    prev_hop, msg_recv = unpack_hive_receive_envelope(dec2)
    report["steps"]["b_decode"] = {"ok": True, "prev_hop_id": prev_hop, "msg_sha256": _sha256(json.dumps(msg_recv, sort_keys=True).encode("utf-8"))}
    c_recv, b_recv = _post(b + "/hive/v12/receive", {"prev_hop_id": prev_hop, "msg": msg_recv}, timeout=60)
    report["steps"]["b_receive"] = {"code": c_recv, "body": b_recv}
    print(f"[B] receive status: {b_recv}")
    if bool(args.play_b):
        _maybe_play_wav(out_wav)

    # EVE tries header tamper (dst change) with a fresh nonce to avoid replay short-circuit.
    # This must fail as "corrupt" because AAD changes but tag is not forgeable.
    tam = dict(msg_recv)
    tam["dst_node_id"] = e_id
    tam["nonce"] = int(msg_recv.get("nonce", 0)) + 1
    c_tam, b_tam = _post(b + "/hive/v12/receive", {"prev_hop_id": prev_hop, "msg": tam}, timeout=30)
    report["steps"]["eve_tamper_dst_to_b"] = {"code": c_tam, "body": b_tam}

    # EVE tries replay to B (expected replay if B accepted above)
    c_rep, b_rep = _post(b + "/hive/v12/receive", {"prev_hop_id": prev_hop, "msg": msg_recv}, timeout=30)
    report["steps"]["eve_replay_to_b"] = {"code": c_rep, "body": b_rep}

    os.makedirs("logs", exist_ok=True)
    out = os.path.join("logs", f"idre_silence_wire_demo_{int(time.time())}.json")
    Path(out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"WROTE {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
