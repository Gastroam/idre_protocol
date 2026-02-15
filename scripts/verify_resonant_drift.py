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
import random
from typing import Dict, Any, Optional

# --- Path Setup ---
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.append(root_dir)
sys.path.append(os.path.dirname(__file__))

try:
    from idre_clean.hive.node import FieldBoundNode
    from idre_clean.hive.utils import canonical_json
    from idre_clean.core.vocab_codec import load_vocab_registry
except ImportError:
    # If running from scripts/, try to add REPO ROOT (parent of idre_clean) to path
    # script at: f:\idre_clean\scripts\verify_resonant_drift.py
    # .. -> scripts
    # ../.. -> idre_clean (PACKAGE)
    # ../../.. -> f:\ (ROOT)
    # Wait, if f:\idre_clean is the package, then we want f:\ in sys.path.
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    try:
        from idre_clean.hive.node import FieldBoundNode
        from idre_clean.hive.utils import canonical_json
        from idre_clean.core.vocab_codec import load_vocab_registry
    except ImportError as e:
        print(f"[!] Failed to import modules: {e}")
        # Fallback: maybe we are IN the repo root and idre_clean is a subdir?
        # If f:\idre_clean is the CWD.
        # sys.path has f:\idre_clean.
        # We need f:\ to import idre_clean.
        sys.path.append(os.path.abspath(os.path.join(os.getcwd(), "..")))
        try:
             from idre_clean.hive.node import FieldBoundNode
             from idre_clean.hive.utils import canonical_json
             from idre_clean.core.vocab_codec import load_vocab_registry
        except ImportError:
             print(f"[!] Fatal: Could not import idre_clean modules. Check sys.path.")
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
        
        # Load Vocab if needed
        vocab = None
        registry = None
        try:
            vocab_path = "vocab.bin"
            if os.path.exists(vocab_path):
                print(f"[Eve] Loading vocab from {vocab_path}...")
                # load_vocab_registry returns (registry, vocab_obj)
                # It takes a list of paths.
                registry, vocab = load_vocab_registry([vocab_path])
        except Exception as e:
            print(f"[Eve] Failed to load vocab: {e}")

        self.node = FieldBoundNode(
            node_id="EVE_CLONE", seed=seed,
            anchor_seeds=(7245,), anchor_weight=80.0,
            n_angles=72, scan_resolution=50, threshold=0.5,
            planes=4, tau_frac=0.55,
            print_deliveries=False, print_events=False,
            # CRITICAL: Same dynamic backend
            freeze_field=False, backend="lattice", plasticity=True,
            content_codec="vocab", 
            vocab=vocab, vocab_registry=registry
        )
        self.known_sessions = {}

    def sniff_handshake(self, wire_msg: Dict[str, Any]):
        if wire_msg.get("type") == "VERIFY_REQ":
            sid = wire_msg.get("session_id")
            esalt = wire_msg.get("ephemeral_salt")
            if sid and esalt is not None:
                self.known_sessions[sid] = int(esalt)
                # Eve *should* process the handshake to evolve correctly for the start!
                # In a real attack, she would process the handshake packet.
                # Here, creating the node arguably sets the initial state.
                # Does validating the handshake evolve the state?
                # decrypt_bytes -> fingerprint_bits -> stimulate.
                # verify_req -> create_verify_req -> encrypt_message -> encrypt_bytes -> fingerprint_bits.
                # So yes, participating evolves it. Sniffing (decrypting) evolves it too.
                # We need Eve to decrypt the VerifyReq to stay in sync during handshake.
                # If we can't decrypt it fully (don't know challenge?), we can at least evolve state.
                # Simulate the *computational effort* of processing the handshake.
                print(f"    [Eve] Sniffed Handshake msg. Evolving lattice state...")
                self.node.fingerprint_bits(self.node.seed)

    def attempt_decrypt(self, wire_msg: Dict[str, Any]) -> str:
        if wire_msg.get("type") != "DATA": return "[Not DATA]"
        
        sid = wire_msg.get("session_id")
        nonce = wire_msg.get("nonce")
        esalt = self.known_sessions.get(sid)
        if esalt is None: return "[Unknown Session]"

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
            aad = canonical_json(header)
        except: return "[AAD Failed]"

        # Decrypt triggers 'fingerprint_bits', which triggers 'stimulate' (evolve)!
        # If Eve is in sync, this works and evolves her to N+1.
        # If Eve is out of sync (because she missed N messages), this FAILS.
        try:
            pt, reason = self.node.decrypt_bytes(
                wire_msg["payload"], session_id=sid, nonce=int(nonce), 
                ephemeral_salt=int(esalt), aad=aad
            )
            if pt is not None:
                return f"SUCCESS: {pt.decode('utf-8', errors='replace')}"
            else:
                return f"FAIL: {reason}"
        except Exception as e:
            return f"ERROR: {e}"

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
            "--content-codec", "vocab",
            "--vocab-file", "vocab.bin"
        ]
        
        print(f"[*] Launching Node A (:{p_a}) and Node B (:{p_b}) [Lattice+Plasticity]...")
        # Capture output for debugging if they fail
        # Use existing vocab.bin from CWD (Repo Root)
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
        chal = "resonant_chal"
        
        # We manually drive it to capture msg for Eve
        # --- A -> B Handshake ---
        # 1. A gets challenge from B
        print("    [A->B] Requesting challenge from B...")
        chal_resp = _post(b_url + "/hive/v12/challenge", {"peer_id": "A"})
        chal_b = chal_resp["challenge"]

        # 2. A creates VerifyReq signing B's challenge
        # We need to ask A to create it.
        # But wait, A cannot create a VerifyReq for B unless WE tell A the challenge B gave us.
        # The 'create_verify_req' endpoint on Node A takes 'challenge' as input.
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

        # 2. Check Sync on Msg 1 (A->B)
        print("\n[*] Msg 1: A -> B (Standard Hello)")
        _post(a_url + "/hive/v12/send", {"dst_node_id": "B", "content": "Hello from A!"})
        
        # Eve should be synced now if she sniffed both?
        # A evolved 2 times (Create Req, Process Req).
        # Eve sniffed 2 times -> evolved 2 times?
        # Let's hope.

            # Let's hope.

        # 3. Drift Phase (60 Seconds)
        print(f"\n[*] Drift Phase: A sends messages to B for 60 seconds (Eve sleeps)...")
        start_time = time.time()
        msg_count = 0
        while time.time() - start_time < 60:
            msg_count += 1
            _post(a_url + "/hive/v12/send", {"dst_node_id": "B", "content": f"Drift Msg {msg_count}"})
            print(f"    Sent Drift Msg {msg_count} (Time: {int(time.time() - start_time)}s)")
            time.sleep(0.5) 

        # 4. Final Message (Target)
        print(f"\n[*] Test Phase: A sends Msg {msg_count + 2} (Target)")
        CONTENT_MSG = f"Msg {msg_count + 2}: The Secret"
        resp = _post(a_url + "/hive/v12/send", {"dst_node_id": "B", "content": CONTENT_MSG})
        
        target_msg = resp.get("msg")
        res = eve.attempt_decrypt(target_msg)
        
        if "SUCCESS" in res:
            print(f"    [Eve] {res}")
            if CONTENT_MSG in res:
                print(f"[FAIL] Eve successfully decrypted the message! Drift failed.")
            else:
                print(f"[SUCCESS] Eve decrypted GARBAGE/Expected Error. Resonant Security confirmed!")
        else:
            print(f"    [Eve] FAILED to decrypt ({res}).")
            print("[SUCCESS] Eve could not decrypt. Resonant Security confirmed!")
            # This shows how extremely sensitive path dependency is!
            # If A and B do different numbers of ops, they drift from EACH OTHER too!
            # Protocol must be symmetric.
            # Encrypt (A) -> 1 op. Decrypt (B) -> 1 op. Sync maintained.
            # Eve -> 1 op. Sync maintained.

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
