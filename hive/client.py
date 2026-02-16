
import json
import urllib.request
import urllib.error
from typing import Dict, Any, Tuple, Optional

def _post(url: str, payload: Dict[str, Any], timeout: int = 10) -> Tuple[int, Dict[str, Any]]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            code = r.getcode()
            body = r.read().decode("utf-8")
            return code, json.loads(body)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(body)
        except Exception:
            return exc.code, {"error": "http_error", "status": exc.code, "body": body}
    except Exception as e:
        return 0, {"error": str(e)}

class HiveClient:
    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        
    def hello(self) -> Dict[str, Any]:
        c, r = _post(f"{self.base_url}/hive/v12/hello", {}, timeout=self.timeout)
        if c == 200:
            return r
        return {}

    def get_challenge(self, peer_id: str) -> Optional[str]:
        c, r = _post(f"{self.base_url}/hive/v12/challenge", {"peer_id": peer_id}, timeout=self.timeout)
        if c == 200:
            return r.get("challenge")
        return None

    def create_verify_req(self, session_id: str, ephemeral_salt: int, challenge: str) -> Optional[Dict[str, Any]]:
        c, r = _post(
            f"{self.base_url}/hive/v12/verify_req/create", 
            {"session_id": session_id, "ephemeral_salt": ephemeral_salt, "challenge": challenge}, 
            timeout=self.timeout
        )
        if c == 200:
            return r.get("msg")
        return None

    def process_verify_req(self, peer_id: str, msg: Dict[str, Any], ttl_s: int = 600) -> bool:
        c, r = _post(
            f"{self.base_url}/hive/v12/verify_req/process", 
            {"peer_id": peer_id, "msg": msg, "ttl_s": ttl_s}, 
            timeout=self.timeout
        )
        return c == 200 and r.get("verified")

    def force_session(self, peer_id: str, session_id: str, ephemeral_salt: int) -> bool:
        c, r = _post(
            f"{self.base_url}/hive/v12/debug/force_session", 
            {"peer_id": peer_id, "session_id": session_id, "ephemeral_salt": ephemeral_salt}, 
            timeout=self.timeout
        )
        return c == 200 and r.get("forced")

    def send(self, dst_node_id: str, content: str, created_at_ms: Optional[int] = None) -> Optional[Dict[str, Any]]:
        payload = {"dst_node_id": dst_node_id, "content": content}
        if created_at_ms is not None:
             payload["created_at_ms"] = created_at_ms
             
        c, r = _post(f"{self.base_url}/hive/v12/send", payload, timeout=self.timeout)
        if c == 200:
            return r.get("msg")
        return None

    def receive(self, prev_hop_id: str, wire_msg: Dict[str, Any]) -> str:
        c, r = _post(
            f"{self.base_url}/hive/v12/receive", 
            {"prev_hop_id": prev_hop_id, "msg": wire_msg}, 
            timeout=self.timeout
        )
        if c != 200: 
            return f"HTTP_{c}"
        
        result = r.get("result", {})
        status = r.get("status")
        
        if isinstance(result, dict) and "status" in result:
            return result["status"]
        elif status:
            return status
        return "unknown"
