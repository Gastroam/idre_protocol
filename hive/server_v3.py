"""IDRE v3 HTTP Server wrapping FieldBoundNodeV3 (isolated from v2 hive/server.py)."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Any, Dict, Tuple

from core.profile_v3 import MAX_WIRE_CELL_BYTES
from hive.engine_v3 import EngineError
from hive.key_schedule_v3 import KeyScheduleError
from hive.node_v3 import FieldBoundNodeV3
from hive.state_store_v3 import StateStoreError


class _ThreadedHTTPServerV3(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class HandlerV3(BaseHTTPRequestHandler):
    server_version = "HiveV3/3.0"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def _require_local(self) -> bool:
        ip = str(getattr(self, "client_address", ("", 0))[0])
        if ip not in ("127.0.0.1", "::1"):
            self._json(403, {"error": "internal_only"})
            return False
        return True

    def _json(self, code: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self, max_bytes: int = 32768) -> Tuple[bool, Dict[str, Any]]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length > max_bytes:
            self._json(413, {"error": "payload_too_large"})
            return False, {}
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            self._json(400, {"error": "bad_json"})
            return False, {}
        if not isinstance(data, dict):
            self._json(400, {"error": "bad_json_object"})
            return False, {}
        return True, data

    def do_GET(self) -> None:
        node: FieldBoundNodeV3 = self.server.node  # type: ignore[attr-defined]
        if self.path == "/health":
            self._json(200, {"status": "ok", "proto": node.profile.protocol_version, "node_id": node.node_id})
            return
        if self.path == "/hive/v3/hello":
            self._json(200, node.hello())
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        node: FieldBoundNodeV3 = self.server.node  # type: ignore[attr-defined]
        ok, body = self._read_json()
        if not ok:
            return

        try:
            if self.path == "/hive/v3/handshake/init":
                if not self._require_local():
                    return
                self._json(200, node.handshake_init(str(body["peer_id"])))
                return

            if self.path == "/hive/v3/handshake/respond":
                self._json(200, node.handshake_respond(body))
                return

            if self.path == "/hive/v3/handshake/finish_initiator":
                if not self._require_local():
                    return
                self._json(200, node.handshake_finish_initiator(str(body["peer_id"]), dict(body["resp"])))
                return

            if self.path == "/hive/v3/handshake/finish_responder":
                verified = node.handshake_finish_responder(str(body["peer_id"]), dict(body["finish"]))
                self._json(200, {"verified": verified})
                return

            if self.path == "/hive/v3/send":
                if not self._require_local():
                    return
                pkt = node.send(str(body["peer_id"]), str(body["content"]))
                self._json(200, {"packet_hex": pkt.hex()})
                return

            if self.path == "/hive/v3/retransmit":
                if not self._require_local():
                    return
                pkt = node.retransmit(str(body["peer_id"]))
                self._json(200, {"packet_hex": pkt.hex() if pkt is not None else None})
                return

            if self.path == "/hive/v3/receive":
                pkt = bytes.fromhex(str(body["packet_hex"]))
                if len(pkt) > MAX_WIRE_CELL_BYTES:
                    self._json(413, {"status": "reject", "reason": "oversize_wire_cell"})
                    return
                res = node.receive(str(body["peer_id"]), pkt)
                self._json(200, res)
                return

            if self.path == "/hive/v3/ack":
                ack = bytes.fromhex(str(body["ack_hex"]))
                if len(ack) > MAX_WIRE_CELL_BYTES:
                    self._json(413, {"status": "reject", "reason": "oversize_wire_cell"})
                    return
                res = node.process_ack(str(body["peer_id"]), ack)
                self._json(200, res)
                return

            if self.path == "/hive/v3/inbox":
                if not self._require_local():
                    return
                self._json(200, {"records": node.inbox(str(body["peer_id"]))})
                return

            self._json(404, {"error": "not_found"})
        except (KeyError, ValueError, KeyScheduleError, EngineError, StateStoreError) as exc:
            reason = getattr(exc, "reason", str(exc))
            self._json(400, {"status": "reject", "reason": reason})


def create_server_v3(node: FieldBoundNodeV3, *, host: str = "127.0.0.1", port: int = 0) -> _ThreadedHTTPServerV3:
    srv = _ThreadedHTTPServerV3((host, int(port)), HandlerV3)
    srv.node = node  # type: ignore[attr-defined]
    return srv
