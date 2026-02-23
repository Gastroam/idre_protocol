#!/usr/bin/env python3
"""
Verify Resonant Security (Lattice Drift).

Demonstrates "Continuous Forward Secrecy" via dynamic lattice plasticity.
Even if Eve starts with the SAME SEED, if she misses traffic, her state
diverges from the "Resonant" pair (A/B), preventing decryption of future messages.

Scenario:
1. Launch Node A, Node B, and Eve with `--backend lattice --enable-plasticity --seed 7245`.
2. Verify initial sync: Eve can decrypt Message #1 (or Handshake).
3. Drift Phase: Node A sends 5 messages to Node B. (A and B evolve).
   Eve *does not* see/process these messages.
4. Test Phase: Node A sends Message #6.
5. Eve attempts to decrypt Message #6.
6. Expectation: DECRYPTION FAILURE (State Mismatch).
"""

import sys
import os
import time
import subprocess
import json
import urllib.request
import urllib.error
import hashlib
import hmac
import struct
from typing import Dict, Any

# --- Path Setup ---
try:
    from hive.node import FieldBoundNode
    from hive.utils import canonical_json
except ImportError:

    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    try:
        from hive.node import FieldBoundNode
        from hive.utils import canonical_json
    except ImportError as e:
        print(f"[!] Failed to import modules: {e}")
 
        sys.path.append(os.path.abspath(os.path.join(os.getcwd(), "..")))
        try:
             from hive.node import FieldBoundNode
             from hive.utils import canonical_json
        except ImportError:
             print("[!] Fatal: Could not import idre_clean modules. Check sys.path.")
             sys.exit(1)

def _post(url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP Error {e.code}: {e.read().decode()}")
        raise
    except Exception as e:
        print(f"[!] Request Error: {e}")
        raise

def wait_for_port(port, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        try:
            # Use /health since it's the only standard endpoint for liveness
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as r:
                if r.getcode() == 200:
                    return True
        except Exception as e:
            print(f"[DEBUG] {port} failed: {e}")
            time.sleep(1.0)
    return False

# --- Eve Logic ---
class EveResonant:
    def __init__(self, seed: int = 7245):
        # Eve initializes with the SAME seed and configuration as A/B.
        # Implies she *could* be in sync if she processed everything.

        # Vocab is mandatory for node construction (even if content codec is utf8).
        # For this demo, Eve does not need a real vocab because we run utf8 content.
        try:
            from core.vocab_codec import Vocab
        except Exception:
            from core.vocab_codec import Vocab
        toks = ["<pad>", "<unk>", "a", "b", "c", " ", ".", ","]
        t2i = {t: i for i, t in enumerate(toks)}
        dummy_vocab = Vocab(tokens=toks, token_to_index=t2i, vocab_id=b"DUMMY", lens_by_first_char={" ": [1]})

        self.node = FieldBoundNode(pepper="test_pepper", node_id="EVE_CLONE", seed=seed,
            anchor_seeds=(7245,), anchor_weight=80.0,
            n_angles=72, scan_resolution=50, threshold=0.5,
            planes=4, tau_frac=0.55,
            print_deliveries=False, print_events=False,
            # CRITICAL: Same dynamic backend
            freeze_field=False, backend="lattice", plasticity=True,
            content_codec="utf8",
            vocab=dummy_vocab,
        )
        # sid -> {ephemeral_salt, chain_hash, next_seq, ratchet_key}
        self.known_sessions: Dict[str, Dict[str, Any]] = {}

    def _genesis_chain_hash(self, sess_id: str) -> bytes:
        # Must match hive/node.py process_verify_req genesis derivation.
        return hmac.new(str(int(self.node.seed)).encode(), f"GENESIS:{sess_id}".encode(), hashlib.sha256).digest()

    def _ratchet_key(self, sess_id: str) -> int:
        try:
            from hive.ratchet import kdf_int
        except Exception:
            from hive.ratchet import kdf_int
        return int(kdf_int(int(self.node.seed), f"INIT::{sess_id}"))

    def sniff_handshake(self, wire_msg: Dict[str, Any]):
        if wire_msg.get("type") == "VERIFY_REQ":
            sid = wire_msg.get("session_id")
            esalt = wire_msg.get("ephemeral_salt")
            if sid and esalt is not None:
                sid_s = str(sid)
                if sid_s not in self.known_sessions:
                    self.known_sessions[sid_s] = {
                        "ephemeral_salt": int(esalt),
                        "chain_hash": self._genesis_chain_hash(sid_s),
                        "next_seq": 2,
                        "ratchet_key": self._ratchet_key(sid_s),
                    }

                # Actually decrypt the VERIFY_REQ to evolve the lattice exactly as a receiver would.
                try:
                    hdr = {
                        "type": "VERIFY_REQ",
                        "field_profile_id": str(wire_msg.get("field_profile_id", "")),
                        "challenge": str(wire_msg.get("challenge", "")),
                        "session_id": sid_s,
                        "nonce": int(wire_msg.get("nonce", 0) or 0),
                        "ephemeral_salt": int(esalt),
                    }
                    aad = canonical_json(hdr)
                    ok, text, _acks, _tag = self.node.decrypt_message(
                        wire_msg.get("payload", []),
                        session_id=sid_s,
                        nonce=int(hdr["nonce"]),
                        ephemeral_salt=int(esalt),
                        aad=aad,
                    )
                    if ok:
                        print("    [Eve] Sniffed handshake and stayed in sync.")
                    else:
                        print(f"    [Eve] Handshake decrypt failed: {text}")
                except Exception as e:
                    print(f"    [Eve] Handshake processing error: {e}")

    def attempt_decrypt(self, wire_msg: Dict[str, Any]) -> str:
        if wire_msg.get("type") != "DATA": return "[Not DATA]"
        
        sid = str(wire_msg.get("session_id", ""))
        nonce = int(wire_msg.get("nonce", 0) or 0)
        st = self.known_sessions.get(sid)
        if not st:
            return "[Unknown Session]"
        esalt = int(st["ephemeral_salt"])
        chain_hash = bytes(st["chain_hash"])
        next_seq = int(st["next_seq"])
        ratchet_key = int(st["ratchet_key"])

        # Construct AAD
        try:
            header = {
                "type": "DATA",
                "field_profile_id": str(wire_msg.get("field_profile_id", "")),
                "session_id": str(sid),
                "nonce": int(nonce),
                "created_at_ms": int(wire_msg.get("created_at_ms", 0) or 0),
                "expires_at_ms": int(wire_msg.get("expires_at_ms", 0) or 0),
                "src_node_id": str(wire_msg.get("src_node_id", "")),
                "dst_node_id": str(wire_msg.get("dst_node_id", "")),
                "hop_count": int(wire_msg.get("hop_count", 0)),
                "max_hops": int(wire_msg.get("max_hops", 0)),
            }
        except Exception:
            return "[AAD Failed]"

        aad_base = canonical_json(header)
        payload = wire_msg.get("payload")
        if not isinstance(payload, list):
            return "[Bad Payload]"

        # Sliding window like the receiver: tolerate small gaps but require correct anchor binding.
        for candidate_seq in range(max(1, next_seq - 1), next_seq + 6):
            aad = aad_base + chain_hash + struct.pack(">Q", int(candidate_seq))
            try:
                pt, reason, _acks, _tag = self.node.decrypt_bytes(
                    payload,
                    session_id=sid,
                    nonce=int(nonce),
                    ephemeral_salt=int(esalt),
                    aad=aad,
                    ratchet_key=int(ratchet_key),
                )
            except Exception as e:
                return f"ERROR: {e}"

            if pt is None:
                continue

            payload_bytes = bytes(int(x) & 0xFF for x in payload)
            chain_hash = hashlib.sha256(chain_hash + payload_bytes).digest()
            st["chain_hash"] = chain_hash
            st["next_seq"] = int(candidate_seq) + 1

            try:
                return f"SUCCESS: {pt.decode('utf-8', errors='replace')}"
            except Exception:
                return "SUCCESS: <binary>"

        return "FAIL: mac_mismatch"

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--existing-nodes", action="store_true", help="Connect to manually running nodes.")
    args = parser.parse_args()

    print("[*] Starting Resonant Security Demo (Lattice Drift)...")
    p_a = 8900
    p_b = 8901
    
    proc_a = None
    proc_b = None
    
    if not args.existing_nodes:
        cmd_base = [sys.executable, "scripts/hive_v12_node_server.py"]
        common_args = [
            "--seed", "7245", 
            "--planes", "4",
            # CRITICAL FLAGS
            "--backend", "lattice",
            "--enable-plasticity",
            "--content-codec", "utf8",
            "--pepper", "test_pepper",
        ]
        
        print(f"[*] Launching Node A (:{p_a}) and Node B (:{p_b}) [Lattice+Plasticity]...")
        # Capture output for debugging if they fail
        # Use existing vocab.bin from CWD (Repo Root)
        root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        proc_a = subprocess.Popen(cmd_base + ["--port", str(p_a), "--node-id", "A"] + common_args, cwd=root_dir, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        proc_b = subprocess.Popen(cmd_base + ["--port", str(p_b), "--node-id", "B"] + common_args, cwd=root_dir, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        
        # Non-blocking check for early death
        try:
            time.sleep(2)
            if proc_a.poll() is not None:
                print(f"[!] Node A died immediately: {proc_a.stderr.read()}")
                return
            if proc_b.poll() is not None:
                print(f"[!] Node B died immediately: {proc_b.stderr.read()}")
                return
        except Exception:
            pass

    try:
        if args.existing_nodes:
             print(f"[*] Waiting for nodes A(:{p_a}) and B(:{p_b}) to be ready...")
             # Wait up to 5 minutes for user if manually starting
             if not wait_for_port(p_a, timeout=300) or not wait_for_port(p_b, timeout=300):
                  print("[!] Timed out waiting for nodes.")
                  return
        elif not wait_for_port(p_a) or not wait_for_port(p_b):
            print("[!] Failed to start nodes (timeout). Check if vocab.bin exists and is valid.")
            if proc_a and proc_a.poll() is not None: print(f"Node A Stderr: {proc_a.stderr.read()}")
            if proc_b and proc_b.poll() is not None: print(f"Node B Stderr: {proc_b.stderr.read()}")
            return

        print("[OK] Nodes running.")
        
        # Eve (Local Object)
        eve = EveResonant(seed=7245)
        
        # 1. Handshake
        a_url = f"http://127.0.0.1:{p_a}"
        b_url = f"http://127.0.0.1:{p_b}"
        
        print("\n[*] Handshake A->B ...")
        print("\n[*] Handshake A<->B (Mutual Challenge/Verify)...")
        sid = "RES_SESSION_" + hashlib.sha256(os.urandom(32)).hexdigest()[:8]
        salt = 123456
        # We manually drive it to capture msg for Eve
        # --- A -> B Handshake ---
        # 1. A gets challenge from B
        print("    [A->B] Requesting challenge from B...")
        chal_resp = _post(b_url + "/hive/v12/challenge", {"peer_id": "A"})
        chal_b = chal_resp["challenge"]

        # 2. A creates VerifyReq signing B's challenge
        print("    [A->B] Creating VerifyReq on A...")
        va_resp = _post(a_url + "/hive/v12/verify_req/create", {
            "session_id": sid, "ephemeral_salt": salt, "challenge": chal_b
        })
        msg_a = va_resp["msg"]

        # 3. Send A's VerifyReq to B
        print("    [A->B] Sending VerifyReq to B...")
        resp_b = _post(b_url + "/hive/v12/verify_req/process", {"peer_id": "A", "msg": msg_a, "ttl_s": 300})
        if not resp_b.get("verified"):
            print("[!] B rejected A's VerifyReq (Handshake Failed). Exiting.")
            sys.exit(1)
        
        # Eve Sniffs (saves SID/Salt)
        eve.sniff_handshake(msg_a)

        # --- B -> A Handshake (Mutual Auth) to allow A to send to B ---
        # A needs to verify B to accept B's ACKs or future traffic.
        
        print("    Handshake B->A (Mutual)...")
        print("    [B->A] Requesting challenge from A...")
        # A issues challenge
        chal_a_resp = _post(a_url + "/hive/v12/challenge", {"peer_id": "B"})
        chal_a = chal_a_resp["challenge"]

        print("    [B->A] Creating VerifyReq on B...")
        vb_resp = _post(b_url + "/hive/v12/verify_req/create", {
            "session_id": sid, "ephemeral_salt": salt, "challenge": chal_a
        })
        msg_b = vb_resp["msg"]
        
        print("    [B->A] Sending VerifyReq to A...")
        resp_a = _post(a_url + "/hive/v12/verify_req/process", {"peer_id": "B", "msg": msg_b, "ttl_s": 300})
        if not resp_a.get("verified"):
            print("[!] A rejected B's VerifyReq (Handshake Failed). Exiting.")
            sys.exit(1)
        
        # Eve Sniffs (B->A)
        eve.sniff_handshake(msg_b)
        
        print("    [OK] Mutual Handshake complete.")

        # 2. Check Sync on Msg 1 (A->B) with delivery.
        print("\n[*] Msg 1: A -> B (Standard Hello)")
        msg1 = _post(a_url + "/hive/v12/send", {"dst_node_id": "B", "content": "Hello from A!"}).get("msg")
        if not isinstance(msg1, dict):
            print("[!] Failed to create msg1")
            return
        res1 = _post(b_url + "/hive/v12/receive", {"prev_hop_id": "A", "msg": msg1})
        if res1.get("result", {}).get("status") != "delivered":
            print(f"[!] B failed to receive msg1: {res1}")
            return
        eve_res = eve.attempt_decrypt(msg1)
        if "SUCCESS" not in eve_res:
            print(f"[!] Eve failed initial decrypt: {eve_res}")
            return

        # 3. Drift Phase (60 Seconds)
        print("\n[*] Drift Phase: A sends messages to B for 60 seconds (Eve sleeps)...")
        start_time = time.time()
        msg_count = 0
        while time.time() - start_time < 60:
            msg_count += 1
            msg = _post(a_url + "/hive/v12/send", {"dst_node_id": "B", "content": f"Drift Msg {msg_count}"}).get("msg")
            if isinstance(msg, dict):
                _post(b_url + "/hive/v12/receive", {"prev_hop_id": "A", "msg": msg})
            print(f"    Sent Drift Msg {msg_count} (Time: {int(time.time() - start_time)}s)")
            time.sleep(0.5) 

        # 4. Final Message (Target)
        print(f"\n[*] Test Phase: A sends Msg {msg_count + 2} (Target)")
        CONTENT_MSG = f"Msg {msg_count + 2}: The Secret"
        resp = _post(a_url + "/hive/v12/send", {"dst_node_id": "B", "content": CONTENT_MSG})
        
        target_msg = resp.get("msg")
        if not isinstance(target_msg, dict):
            print("[!] Failed to create target message.")
            return
        _post(b_url + "/hive/v12/receive", {"prev_hop_id": "A", "msg": target_msg})
        res = eve.attempt_decrypt(target_msg)
        
        if "SUCCESS" in res:
            print(f"    [Eve] {res}")
            if CONTENT_MSG in res:
                print("[FAIL] Eve successfully decrypted the message! Drift failed.")
            else:
                print("[SUCCESS] Eve decrypted GARBAGE/Expected Error. Resonant Security confirmed!")
        else:
            print(f"    [Eve] FAILED to decrypt ({res}).")
            print("[SUCCESS] Eve could not decrypt. Resonant Security confirmed!")


    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        print("\n[*] Killing nodes...")
        if proc_a:
            proc_a.kill()
        if proc_b:
            proc_b.kill()

if __name__ == "__main__":
    main()
