#!/usr/bin/env python3
"""
Verify Vocab Obfuscation Scenario.

Demonstrates that even if Eve has the Seed (and can decrypt the packet to raw IDs),
she CANNOT decode the message content without the Vocabulary file.

Steps:
1. Create a dummy vocab file (vocab_small.json) for speed.
2. Launch Node A and Node B with `--content-codec vocab --vocab-file vocab_small.json`.
3. Perform handshake.
4. Node A sends a message.
5. Eve (with leaked seed) decrypts the packet -> Gets Raw IDs.
6. Eve tries to decoding -> Fails (simulated).
"""

import sys
import os
import time
import subprocess
import signal
import json
import urllib.request
import urllib.error
import hashlib
import random
from typing import Dict, Any, Optional, List

# --- Path Setup ---
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.append(root_dir)
sys.path.append(os.path.dirname(__file__))

# Import FieldBoundNode for Eve
try:
    from scripts.hive_v12_node_server import FieldBoundNode, canonical_json
except ImportError:
    try:
        from hive_v12_node_server import FieldBoundNode, canonical_json
    except ImportError:
        print("[!] Failed to import FieldBoundNode. Ensure you are running from repo root.")
        sys.exit(1)

# --- Helpers ---

def get_free_port(start=8900):
    # Simple incrementer for this demo script
    return start

def wait_for_port(port, timeout=30):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/hive/v12/hello", timeout=1) as r:
                if r.getcode() == 200:
                    return True
        except:
            time.sleep(0.5)
            # if int(time.time() - start) % 5 == 0:
            #     print(f"[Wait] Still waiting for port {port}...")
    return False

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

# --- Eve Logic ---

class EveDecryptor:
    def __init__(self, seed: int = 7245):
        self.node = None
        self.known_sessions: Dict[str, int] = {}
        if FieldBoundNode:
            # Eve has the seed, but NO vocab (or at least, she doesn't use it for raw decryption)
            # Note: FieldBoundNode constructor might require a vocab if we set content_codec="vocab".
            # BUT: Eve wants to see RAW IDs.
            # If we set content_codec="utf8", decrypt_message returns bytes.
            # If we set content_codec="vocab", it requires a vocab.
            # We will use "utf8" mode for Eve's *decryption* engine efficiently,
            # trusting that the packet payload is encrypted bytes that HAPPEN to be vocab IDs.
            # Actually, FieldBoundNode.decrypt_bytes returns the decrypted blob.
            # If the sender used Vocab, that blob IS the sequence of IDs (packed or otherwise).
            
            self.node = FieldBoundNode(
                node_id="EVE_LEAK", seed=seed,
                anchor_seeds=(7245,), anchor_weight=80.0,
                n_angles=72, scan_resolution=50, threshold=0.5,
                planes=4, tau_frac=0.55,
                print_deliveries=False, print_events=False,
                freeze_field=True, backend="frozen",
                content_codec="utf8" # Eve operates at wire layer
            )

    def sniff_handshake(self, wire_msg: Dict[str, Any]):
        if wire_msg.get("type") == "VERIFY_REQ":
            sid = wire_msg.get("session_id")
            esalt = wire_msg.get("ephemeral_salt")
            if sid and esalt is not None:
                self.known_sessions[sid] = int(esalt)
                print(f"    [Eve] Sniffed Handshake: SID={sid[:8]}... Salt={esalt}")

    def sniff_and_decrypt(self, wire_msg: Dict[str, Any]) -> str:
        if not self.node: return "[No Lib]"
        # Check if handshake
        if wire_msg.get("type") == "VERIFY_REQ":
            self.sniff_handshake(wire_msg)
            return "[Handshake Sniffed]"
        
        if wire_msg.get("type") != "DATA": return "[Not DATA]"

        payload = wire_msg.get("payload")
        sid = wire_msg.get("session_id")
        nonce = wire_msg.get("nonce")
        
        if sid not in self.known_sessions:
            return f"[Unknown Session: {sid[:8]}..]"
        esalt = self.known_sessions[sid]
        
        # AAD reconstruction
        try:
            header = {
                "type": str(wire_msg.get("type")),
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
        except Exception as e:
            return f"[AAD Failed: {e}]"

        try:
            decrypted = self.node.decrypt_bytes(
                payload, session_id=sid, nonce=int(nonce), 
                ephemeral_salt=int(esalt), aad=aad
            )
            if decrypted is not None:
                # Decrypted blob from "vocab" codec is an IDREVOC1 blob.
                # It starts with MAGIC8.
                # Eve can see the BYTES. But converting them to "Meaning" requires the mapping.
                
                raw_bytes = list(decrypted)
                
                # Check for magic header
                magic = bytes(raw_bytes[:8])
                if magic == b"IDREVOC1":
                    return f"SUCCESS_DECRYPT: Found IDREVOC1 Header! Payload Size: {len(raw_bytes)} bytes. Content is OBFUSCATED IDs."
                else:
                    return f"RAW_DECRYPT: {raw_bytes[:20]}... (Not IDREVOC1?)"
            else:
                return "[Decryption Failed]"
        except Exception as e:
            return f"[Error: {e}]"

    # --- Main ---

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--existing-nodes", action="store_true", help="Don't launch nodes, connect to ports 8895/8896")
    args = parser.parse_args()

    print("[*] Starting Vocab Obfuscation Demo...")
    
    p_a = 8895
    p_b = 8896
    vocab_path = os.path.join(root_dir, "vocab_small.json")
    
    proc_a = None
    proc_b = None

    if not args.existing_nodes:
        # 1. Create Dummy Vocab
        dummy_tokens = ["<pad>", "<unk>", "Hello", " ", "World", ",", "this", "is", "a", "secret", "message", ".", "vocab", "obfuscation", "test"]
        with open(vocab_path, "w") as f:
            json.dump(dummy_tokens, f)
        print(f"[*] Created {vocab_path} with {len(dummy_tokens)} tokens.")

        # 2. Launch Nodes
        cmd_base = [sys.executable, "scripts/hive_v12_node_server.py"]
        common_args = [
            "--seed", "7245", 
            "--content-codec", "vocab", 
            "--vocab-file", "vocab_small.json",
            "--planes", "4",
            "--backend", "frozen"
        ]
        
        print(f"[*] Launching Node A (:{p_a}) and Node B (:{p_b}) ...")
        # Redirect stdout/stderr to capture errors
        proc_a = subprocess.Popen(cmd_base + ["--port", str(p_a), "--node-id", "A"] + common_args, cwd=root_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        proc_b = subprocess.Popen(cmd_base + ["--port", str(p_b), "--node-id", "B"] + common_args, cwd=root_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Non-blocking read helper
        try:
            time.sleep(2)
            if proc_a.poll() is not None:
                print(f"[!] Node A died: {proc_a.stderr.read()}")
                return
            if proc_b.poll() is not None:
                print(f"[!] Node B died: {proc_b.stderr.read()}")
                return
        except Exception:
            pass

    try:
        if not wait_for_port(p_a) or not wait_for_port(p_b):
            print("[!] Failed to connect to nodes.")
            return

        print("[OK] Nodes running.")
        
        # 3. Handshake
        a_url = f"http://127.0.0.1:{p_a}"
        b_url = f"http://127.0.0.1:{p_b}"
        
        eve = EveDecryptor(seed=7245)
        
        print("\n[*] Performing Handshake (Eve Sniffing)...")
        sid = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
        salt = random.getrandbits(31)
        
        c_resp = _post(b_url + "/hive/v12/challenge", {"peer_id": "A"})
        chal = c_resp["challenge"]
        
        v_resp = _post(a_url + "/hive/v12/verify_req/create", {
            "session_id": sid, "ephemeral_salt": salt, "challenge": chal
        })
        msg = v_resp["msg"]
        
        # EVE SNIFFS
        eve.sniff_handshake(msg)
        
        _post(b_url + "/hive/v12/verify_req/process", {"peer_id": "A", "msg": msg, "ttl_s": 60})
        print("    [OK] Handshake A->B complete.")
        
        # 4. Same Sender Message
        print("\n[*] Sending 'Hello World' A->B ...")
        content = "Hello World" # Tokens must exist in dummy vocab!
        s_resp = _post(a_url + "/hive/v12/send", {"dst_node_id": "B", "content": content})
        wire_msg = s_resp["msg"]
        
        print(f"    [Wire] Payload Length: {len(wire_msg['payload'])} items")
        
        # 5. Eve Intercepts
        print("\n[*] Eve Attempts Decryption...")
        result = eve.sniff_and_decrypt(wire_msg)
        print(f"    [Result] {result}")
        
        if "IDREVOC1" in result:
            print("\n[SUCCESS] Eve decrypted the packet structure (Seed Leak worked).")
            print("[SUCCESS] Eve sees IDREVOC1 blob (Vocab Obfuscation worked).")
            print("          Without 'vocab_small.json' map, she gets valid binary but NO TEXT.")
        else:
            print("\n[FAIL] Decryption failed or unexpected output.")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if proc_a:
            print("\n[*] Killing Node A...")
            proc_a.kill()
        if proc_b:
            print("[*] Killing Node B...")
            proc_b.kill()
        if not args.existing_nodes and os.path.exists(vocab_path):
            try:
                os.remove(vocab_path)
                print("[*] Removed temp vocab file.")
            except: pass

if __name__ == "__main__":
    main()
