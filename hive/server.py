import json
import threading
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Any, Dict, List, Optional, Tuple

from .utils import _now_ms, DEFAULT_MAX_BODY_BYTES
from .node import FieldBoundNode, DEFAULT_MAX_PAYLOAD_INTS

from idre_clean.core.wire_bin import pack_receive_envelope, pack_wire_message, unpack_receive_envelope
from idre_clean.core.vocab_codec import (
    encode_text as vocab_encode_text,
)

@dataclass
class _Bucket:
    tokens: float
    last: float

class TokenBucketLimiter:
    """Thread-safe token bucket limiter keyed by a string (e.g., client IP)."""

    def __init__(self, *, rate_per_s: float, burst: float, max_keys: int = 50_000, key_ttl_s: float = 300.0):
        self.rate_per_s = float(rate_per_s)
        self.burst = float(burst)
        self.max_keys = int(max_keys)
        self.key_ttl_s = float(key_ttl_s)
        self._lock = threading.Lock()
        self._buckets: Dict[str, _Bucket] = {}
        self._last_sweep = 0.0

    def _sweep(self, now: float, *, force: bool = False) -> None:
        cutoff = float(now) - float(self.key_ttl_s)
        dead = [k for k, b in self._buckets.items() if float(b.last) < cutoff]
        for k in dead:
            self._buckets.pop(k, None)
        if force and len(self._buckets) > self.max_keys:
            items = sorted(self._buckets.items(), key=lambda kv: float(kv[1].last))
            for k, _ in items[: max(0, len(items) - self.max_keys)]:
                self._buckets.pop(k, None)
        self._last_sweep = float(now)

    def allow(self, key: str, *, cost: float = 1.0) -> Tuple[bool, int]:
        kk = str(key)
        now = time.monotonic()
        with self._lock:
            if now - self._last_sweep > 5.0:
                self._sweep(now)

            b = self._buckets.get(kk)
            if b is None:
                if len(self._buckets) >= self.max_keys:
                    self._sweep(now, force=True)
                if len(self._buckets) >= self.max_keys:
                    return False, 1000
                b = _Bucket(tokens=float(self.burst), last=float(now))
                self._buckets[kk] = b

            dt = max(0.0, float(now) - float(b.last))
            b.tokens = min(float(self.burst), float(b.tokens) + dt * float(self.rate_per_s))
            b.last = float(now)

            if float(b.tokens) >= float(cost):
                b.tokens = float(b.tokens) - float(cost)
                return True, 0

            need = float(cost) - float(b.tokens)
            if float(self.rate_per_s) <= 1e-9:
                return False, 1000
            retry_s = need / float(self.rate_per_s)
            return False, int(max(1.0, retry_s * 1000.0))    
    
class _ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(BaseHTTPRequestHandler):
    server_version = "HiveV12/0.1"

    def _json(self, code: int, payload: Dict[str, Any], extra_headers: Optional[Dict[str, str]] = None):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        if extra_headers:
            for k, v in dict(extra_headers).items():
                self.send_header(str(k), str(v))
        self.end_headers()
        self.wfile.write(body)

    def _bytes(self, code: int, body: bytes, *, content_type: str = "application/octet-stream", extra_headers: Optional[Dict[str, str]] = None):
        bb = bytes(body or b"")
        self.send_response(code)
        self.send_header("Content-Type", str(content_type))
        self.send_header("Content-Length", str(len(bb)))
        self.send_header("Access-Control-Allow-Origin", "*")
        if extra_headers:
            for k, v in dict(extra_headers).items():
                self.send_header(str(k), str(v))
        self.end_headers()
        self.wfile.write(bb)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        if self.path == "/health":
            node: FieldBoundNode = self.server.node  # type: ignore[attr-defined]
            now_ms = int(_now_ms())
            self._json(
                200,
                {
                    "status": "ok",
                    "service": "hive_v12_node_server",
                    "proto": "HIVE-P2P/1.2",
                    "server_time_ms": int(now_ms),
                },
            )
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        node: FieldBoundNode = self.server.node  # type: ignore[attr-defined]
        max_body = int(getattr(self.server, "max_body_bytes", DEFAULT_MAX_BODY_BYTES))  # type: ignore[attr-defined]
        if length > max_body:
            self._json(413, {"error": "payload_too_large"})
            return
        raw = self.rfile.read(length) if length > 0 else b"{}"
        
        if self.path == "/hive/v12/receive_wire":
            try:
                prev, msg = unpack_receive_envelope(raw)
            except Exception:
                self._json(400, {"error": "bad_wire"})
                return
            payload = msg.get("payload")
            if isinstance(payload, list) and len(payload) > node.max_payload_ints:
                self._json(413, {"error": "payload_too_large"})
                return
            res = node.receive(msg, prev)
            self._json(200, {"status": "ok", "result": res})
            return

        if self.path == "/hive/v12/ingest_offline":
            client_ip = self.client_address[0]
            if client_ip not in ("127.0.0.1", "::1"):
                self.send_error(403, "internal_only")
                return
            
            blob = raw 
            ok, reason, text = node.ingest_offline_envelope(blob)
            
            if ok:
                self._json(200, {"status": "ok", "text": text, "reason": reason})
            else:
                self._json(200, {"status": "reject", "reason": reason})
            return

        if self.path == "/hive/v12/send_wire":
            try:
                data = json.loads(raw.decode("utf-8")) if raw else {}
            except Exception:
                self._json(400, {"error": "bad_json"})
                return
            dst = str(data.get("dst_node_id", ""))
            content = data.get("content")
            if not dst or not isinstance(content, str):
                self._json(400, {"error": "bad_request"})
                return
            msg = node.send(dst, content, pad_bytes=int(data.get("pad_bytes", 0)))
            if not msg:
                self._json(400, {"error": "no_session_or_expired"})
                return
            prev = str(data.get("prev_hop_id", "") or "")
            try:
                blob = pack_receive_envelope(prev, msg) if prev else pack_wire_message(msg)
            except Exception:
                self._json(500, {"error": "internal"})
                return
            self._bytes(200, blob)
            return

        try:
            data = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            self._json(400, {"error": "bad_json"})
            return

        if self.path == "/hive/v12/hello":
            now_ms = int(_now_ms())
            self._json(
                200,
                {
                    "type": "HELLO",
                    "node_id": node.node_id,
                    "version": "HIVE-P2P/1.2",
                    "field_profile_id": str(getattr(node, "field_profile_id", "")),
                    "server_time_ms": int(now_ms),
                    "server_time_utc": datetime.fromtimestamp(float(now_ms) / 1000.0, tz=timezone.utc).isoformat(),
                },
            )
            return

        if self.path == "/hive/v12/challenge":
            peer_id = str(data.get("peer_id", ""))
            if not peer_id:
                self._json(400, {"error": "bad_request"})
                return
            ip = str(getattr(self, "client_address", ("", 0))[0])
            rl: Optional[TokenBucketLimiter] = getattr(self.server, "rl_challenge_ip", None)  # type: ignore[attr-defined]
            if rl is not None:
                ok, retry_ms = rl.allow(ip)
                if not ok:
                    self._json(
                        429,
                        {"error": "rate_limited", "retry_after_ms": int(retry_ms)},
                        extra_headers={"Retry-After": str(max(1, int(retry_ms // 1000)))},
                    )
                    return
            rec = node.issue_challenge(peer_id=peer_id)
            self._json(
                200,
                {
                    "status": "ok",
                    "challenge": str(rec.challenge),
                    "issued_at_ms": int(rec.issued_at_ms),
                    "expires_at_ms": int(rec.expires_at_ms),
                    "server_time_ms": int(_now_ms()),
                },
            )
            return

        if self.path == "/hive/v12/verify_req/create":
            try:
                session_id = str(data.get("session_id", ""))
                e_salt = int(data.get("ephemeral_salt", 0))
                challenge = str(data.get("challenge", ""))
                msg = node.create_verify_req(session_id=session_id, ephemeral_salt=e_salt, challenge=challenge)
                self._json(200, {"status": "ok", "msg": msg})
            except Exception:
                import traceback
                traceback.print_exc()
                self._json(500, {"error": "internal"})
            return

        if self.path == "/hive/v12/verify_req/process":
            peer_id = str(data.get("peer_id", ""))
            msg = data.get("msg")
            if not peer_id or not isinstance(msg, dict):
                self._json(400, {"error": "bad_request"})
                return
            ip = str(getattr(self, "client_address", ("", 0))[0])
            rl: Optional[TokenBucketLimiter] = getattr(self.server, "rl_verify_ip", None)  # type: ignore[attr-defined]
            if rl is not None:
                ok, retry_ms = rl.allow(ip)
                if not ok:
                    self._json(
                        429,
                        {"error": "rate_limited", "retry_after_ms": int(retry_ms)},
                        extra_headers={"Retry-After": str(max(1, int(retry_ms // 1000)))},
                    )
                    return
            ok = bool(node.process_verify_req(msg, peer_id=peer_id, ttl_s=float(data.get("ttl_s", 600.0))))
            self._json(200, {"status": "ok", "verified": ok})
            return

        if self.path == "/hive/v12/debug/force_session":
            peer_id = str(data.get("peer_id", ""))
            session_id = str(data.get("session_id", ""))
            ephemeral_salt = int(data.get("ephemeral_salt", 0))
            if not peer_id or not session_id:
                self._json(400, {"error": "bad_request"})
                return
            
            try:
                node.force_session(peer_id, session_id, ephemeral_salt)
                self._json(200, {"status": "ok", "forced": True})
            except Exception as e:
                import traceback
                traceback.print_exc()
                self._json(500, {"error": str(e)})
            return

        if self.path == "/hive/v12/send":
            dst = str(data.get("dst_node_id", ""))
            content = data.get("content")
            if not dst or not isinstance(content, str):
                self._json(400, {"error": "bad_request"})
                return

            created_at_ms = data.get("created_at_ms")
            expires_at_ms = data.get("expires_at_ms")
            expires_in_ms = data.get("expires_in_ms")
            
            override_created: Optional[int] = None
            override_expires: Optional[int] = None

            if created_at_ms is not None or expires_at_ms is not None or expires_in_ms is not None:
                now_ms = _now_ms()
                c = int(created_at_ms) if created_at_ms is not None else int(now_ms)
                if expires_at_ms is not None:
                    x = int(expires_at_ms)
                else:
                    delta = int(expires_in_ms) if expires_in_ms is not None else int(node.default_ttl_ms)
                    x = int(c) + int(delta)
                if x <= 0 or c <= 0 or x < c:
                    self._json(400, {"error": "bad_time"})
                    return
                override_created = int(c)
                override_expires = int(x)

            msg = node.send(
                dst, 
                content, 
                pad_bytes=int(data.get("pad_bytes", 0)),
                override_created_at_ms=override_created,
                override_expires_at_ms=override_expires,
            )
            if not msg:
                self._json(400, {"error": "no_session_or_expired"})
                return

            self._json(200, {"status": "ok", "msg": msg})
            return

        if self.path == "/hive/v12/receive":
            prev = str(data.get("prev_hop_id", ""))
            msg = data.get("msg")
            if not prev or not isinstance(msg, dict):
                self._json(400, {"error": "bad_request"})
                return
            res = node.receive(msg, prev)
            self._json(200, {"status": "ok", "result": res})
            return

        self.send_error(404, "not_found")

    def log_message(self, fmt: str, *args):
        return


