"""IDRE v3 HTTP Client for live /hive/v3/* endpoints."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple


def _req(url: str, payload: Optional[Dict[str, Any]] = None, *, method: str = "POST", timeout: int = 10) -> Tuple[int, Dict[str, Any]]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"} if payload is not None else {}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(body)
        except Exception:
            return exc.code, {"error": "http_error", "status": exc.code, "body": body}


class HiveClientV3:
    def __init__(self, base_url: str, *, timeout: int = 10) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def health(self) -> Dict[str, Any]:
        c, r = _req(f"{self.base_url}/health", method="GET", timeout=self.timeout)
        assert c == 200, f"health failed: {c} {r}"
        return r

    def hello(self) -> Dict[str, Any]:
        c, r = _req(f"{self.base_url}/hive/v3/hello", method="GET", timeout=self.timeout)
        assert c == 200, f"hello failed: {c} {r}"
        return r

    def mutual_handshake(self, responder: "HiveClientV3", *, initiator_id: str, responder_id: str) -> str:
        c1, init_msg = _req(f"{self.base_url}/hive/v3/handshake/init", {"peer_id": responder_id}, timeout=self.timeout)
        assert c1 == 200, f"handshake/init failed: {c1} {init_msg}"

        c2, resp_msg = _req(f"{responder.base_url}/hive/v3/handshake/respond", init_msg, timeout=self.timeout)
        assert c2 == 200, f"handshake/respond failed: {c2} {resp_msg}"

        c3, fin_msg = _req(
            f"{self.base_url}/hive/v3/handshake/finish_initiator",
            {"peer_id": responder_id, "resp": resp_msg},
            timeout=self.timeout,
        )
        assert c3 == 200, f"handshake/finish_initiator failed: {c3} {fin_msg}"

        c4, ok_msg = _req(
            f"{responder.base_url}/hive/v3/handshake/finish_responder",
            {"peer_id": initiator_id, "finish": fin_msg},
            timeout=self.timeout,
        )
        assert c4 == 200 and ok_msg.get("verified") is True, f"handshake/finish_responder failed: {c4} {ok_msg}"
        return str(init_msg["session_id_hex"])

    def send(self, peer_id: str, content: str) -> Tuple[int, Dict[str, Any]]:
        return _req(f"{self.base_url}/hive/v3/send", {"peer_id": peer_id, "content": content}, timeout=self.timeout)

    def retransmit(self, peer_id: str) -> Optional[str]:
        c, r = _req(f"{self.base_url}/hive/v3/retransmit", {"peer_id": peer_id}, timeout=self.timeout)
        assert c == 200, f"retransmit failed: {c} {r}"
        return r.get("packet_hex")

    def receive(self, peer_id: str, packet_hex: str) -> Tuple[int, Dict[str, Any]]:
        return _req(
            f"{self.base_url}/hive/v3/receive",
            {"peer_id": peer_id, "packet_hex": packet_hex},
            timeout=self.timeout,
        )

    def ack(self, peer_id: str, ack_hex: str) -> Tuple[int, Dict[str, Any]]:
        return _req(f"{self.base_url}/hive/v3/ack", {"peer_id": peer_id, "ack_hex": ack_hex}, timeout=self.timeout)

    def inbox(self, peer_id: str) -> List[Dict[str, Any]]:
        c, r = _req(f"{self.base_url}/hive/v3/inbox", {"peer_id": peer_id}, timeout=self.timeout)
        assert c == 200, f"inbox failed: {c} {r}"
        return list(r.get("records", []))
