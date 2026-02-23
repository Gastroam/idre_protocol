#!/usr/bin/env python3
"""
IDRE Eve Attack Suite v2 (Advanced)

This suite actively attacks IDRE/Hive v1.2 nodes to test security boundaries.
Modules:
- Recon: Discover nodes and version info.
- Fuzz: Smart payload mutation and endpoint fuzzing.
- Crypto: Timing side-channel analysis and replay testing.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import random
import statistics
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

# --- Utilities ---

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _json_sha(obj: Any) -> str:
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _sha256(blob)

@dataclass
class HttpResult:
    code: int
    body: Any
    latency_ms: float
    error: Optional[str] = None

def _http_req(url: str, method: str = "GET", payload: Optional[Dict[str, Any]] = None, timeout: float = 10.0) -> HttpResult:
    t0 = time.perf_counter()
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8")
            dt = (time.perf_counter() - t0) * 1000.0
            try:
                body = json.loads(raw)
            except json.JSONDecodeError:
                body = raw
            return HttpResult(r.getcode(), body, dt)
    except urllib.error.HTTPError as e:
        dt = (time.perf_counter() - t0) * 1000.0
        raw = e.read().decode("utf-8", errors="replace")
        try:
            body = json.loads(raw)
        except:
            body = raw
        return HttpResult(e.code, body, dt, error=str(e))
    except Exception as e:
        dt = (time.perf_counter() - t0) * 1000.0
        return HttpResult(0, None, dt, error=str(e))

# --- Attack Modules ---

class ReconModule:
    """Discovers node capabilities."""
    def run(self, target: str) -> Dict[str, Any]:
        print(f"[*] Recon target: {target}")
        res_h = _http_req(f"{target}/health")
        res_hello = _http_req(f"{target}/hive/v12/hello", method="POST", payload={})
        
        return {
            "health": {"code": res_h.code, "body": res_h.body},
            "hello": {"code": res_hello.code, "body": res_hello.body},
            "fingerprint": self._fingerprint(res_h.body)
        }

    def _fingerprint(self, body: Any) -> str:
        if not isinstance(body, dict): return "unknown"
        feats = body.get("features", {})
        return f"HiveV1.2/planes={feats.get('planes')}/backend={feats.get('backend')}"

class FuzzModule:
    """Mutates payloads to crash parser or find logic bugs."""
    
    def run(self, target: str, valid_payload: Dict[str, Any], rounds: int = 50) -> List[Dict[str, Any]]:
        print(f"[*] Fuzzing {target} with {rounds} mutations...")
        results = []
        
        # 1. Endpoint Fuzzing (Bad JSON)
        for _ in range(5):
             res = _http_req(f"{target}/hive/v12/receive", method="POST", payload={"broken": "json", "msg": 123})
             results.append({"type": "bad_schema", "code": res.code, "error": res.error})

        # 2. Payload Mutation
        rng = random.Random(1337)
        base = copy.deepcopy(valid_payload)
        
        for i in range(rounds):
            mutated = self._mutate(base, rng)
            # Wrap in receive envelope if it's a raw payload
            envelope = {
                "prev_hop_id": "FUZZER",
                "msg": {
                    "type": "DATA", 
                    "session_id": "FUZZ_SESSION",
                    "nonce": rng.getrandbits(64),
                    "payload": mutated
                }
            }
            res = _http_req(f"{target}/hive/v12/receive", method="POST", payload=envelope)
            results.append({
                "type": "mutation",
                "mutation_id": i,
                "code": res.code, 
                "latency": res.latency_ms
            })
            if res.code == 500:
                print(f"[!] CRASH/500 detected on mutation {i}")
                
        return results

    def _mutate(self, payload: List[int], rng: random.Random) -> Any:
        # Strategies: Bitflip, Truncate, Extend, DataType, Null
        strat = rng.choice(["flip", "trunc", "extend", "type", "null"])
        p = list(payload)
        
        if strat == "flip" and p:
            idx = rng.randrange(len(p))
            p[idx] ^= rng.getrandbits(8)
        elif strat == "trunc" and p:
            cut = rng.randrange(len(p))
            p = p[:cut]
        elif strat == "extend":
            p.extend([rng.getrandbits(8) for _ in range(100)])
        elif strat == "type":
            return "not-a-list-of-ints"
        elif strat == "null":
            return None
            
        return p

class CryptoModule:
    """Analyzes cryptographic implementation flaws."""
    
    def timing_analysis(self, target: str, valid_envelope: Dict[str, Any], samples: int = 100) -> Dict[str, Any]:
        print(f"[*] Timing analysis ({samples} samples/case)...")
        
        cases = {
            "valid": valid_envelope,
            "bad_mac": self._tamper_mac(valid_envelope),
            "bad_ct": self._tamper_ct(valid_envelope),
        }
        
        timings = {k: [] for k in cases}
        
        for _ in range(samples):
            for case_name, payload in cases.items():
                # Randomize nonce to avoid replay cache hits affecting timing? 
                # Actually, we want to hit the crypto path, so fresh nonce is good.
                # But if we tamper MAC, we fail MAC check.
                res = _http_req(f"{target}/hive/v12/receive", method="POST", payload=payload)
                timings[case_name].append(res.latency_ms)
                
        stats = {}
        for k, v in timings.items():
            if not v: continue
            stats[k] = {
                "mean": statistics.mean(v),
                "stdev": statistics.stdev(v) if len(v) > 1 else 0.0,
                "min": min(v),
                "max": max(v)
            }
            
        return stats

    def _tamper_mac(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        c = copy.deepcopy(envelope)
        p = c["msg"]["payload"]
        if isinstance(p, list) and len(p) > 32:
            # Flip last byte (in tag)
            p[-1] ^= 0xFF
        return c

    def _tamper_ct(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        c = copy.deepcopy(envelope)
        p = c["msg"]["payload"]
        if isinstance(p, list) and len(p) > 33:
            # Flip byte in ciphertext (index 1)
            p[1] ^= 0xFF
        return c

# --- Main ---

def main():
    parser = argparse.ArgumentParser(description="IDRE Eve Attack Suite v2")
    parser.add_argument("--target", required=True, help="Target Node URL (e.g. http://localhost:8891)")
    parser.add_argument("--report", default="eve_report.json", help="Output report file")
    # For valid payload generation, we might need a helper or seed.
    # For now, we'll try to sniff or use a dummy.
    args = parser.parse_args()
    
    report = {"target": args.target, "timestamp": time.time(), "modules": {}}
    
    # 1. Recon
    recon = ReconModule()
    report["modules"]["recon"] = recon.run(args.target)
    
    # Generate a dummy "valid" payload structure for fuzzing context
    # In a real attack, we'd capture this. Here we mock a basic one.
    dummy_payload = [10] + [0]*10 + [0]*32 # Mock: [len=10][10 zero bytes][32 byte tag]
    dummy_env = {
        "prev_hop_id": "EVE",
        "msg": {
            "type": "DATA", 
            "session_id": "EVE_SESSION",
            "nonce": 12345,
            "payload": dummy_payload
        }
    }

    # 2. Fuzz
    # For better results in a real scenario, use a captured valid payload.
    # Here we default to a structured dummy, but allow override if args.payload is provided.
    if hasattr(args, 'payload') and args.payload:
        try:
           valid_payload = json.loads(args.payload)
        except:
           print("[!] Invalid JSON in --payload argument, falling back to dummy")
           valid_payload = dummy_payload
    else:
        valid_payload = dummy_payload
        
    fuzzer = FuzzModule()
    # We pass the full envelope structure for context, but mutate the inner payload
    fuzzer_env = copy.deepcopy(dummy_env)
    fuzzer_env["msg"]["payload"] = valid_payload
    
    report["modules"]["fuzz"] = fuzzer.run(args.target, fuzzer_env["msg"]["payload"], rounds=50)

    # 3. Crypto
    crypto = CryptoModule()
    # Use the same valid payload for timing analysis baseline
    crypto_env = copy.deepcopy(dummy_env)
    crypto_env["msg"]["payload"] = valid_payload
    report["modules"]["crypto"] = crypto.timing_analysis(args.target, crypto_env)
    
    # Save
    with open(args.report, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Report saved to {args.report}")

if __name__ == "__main__":
    main()
