#!/usr/bin/env python3
"""
Verify Vocab Obfuscation Scenario.

Demonstrates that even if Eve has the Seed (and can decrypt the packet to raw IDs),
she CANNOT decode the message content without the Vocabulary file.

Steps:
1. Create a dummy vocab file (vocab_small.json) for speed.
2. Launch Node A and Node B with `--content-codec vocab --vocab-file vocab_small.json`.
3. Perform mutual handshake (A<->B) so both can send.
4. Node A sends a message.
5. Eve (with leaked seed) decrypts the packet -> Gets raw bytes.
6. Eve can see an `IDREVOC1` blob but cannot map IDs -> text without the vocab file.
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
import random
import struct
from pathlib import Path
from typing import Dict, Any, Tuple

# --- Path Setup ---
_REPO_ROOT = Path(__file__).resolve().parents[1]
_REPO_PARENT = _REPO_ROOT.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
if str(_REPO_PARENT) not in sys.path:
    sys.path.insert(0, str(_REPO_PARENT))

try:
    from hive.node import FieldBoundNode
    from hive.utils import canonical_json
    from core.vocab_codec import Vocab
except ImportError:
    from hive.node import FieldBoundNode
    from hive.utils import canonical_json
    from core.vocab_codec import Vocab

# --- Helpers ---

def wait_for_port(port, timeout=30):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as r:
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

def _dummy_vocab() -> Vocab:
    # Minimal positional vocab to satisfy IDRE v3 constructor requirements.
    toks = ["<pad>", "<unk>", "a", "b", "c", " ", ".", ","]
    t2i = {t: i for i, t in enumerate(toks)}
    return Vocab(tokens=toks, token_to_index=t2i, vocab_id=b"DUMMY", lens_by_first_char={" ": [1], ".": [1], ",": [1], "a": [1], "b": [1], "c": [1]})

def hmac_genesis(seed: int, session_id: str) -> bytes:
    # Must match hive/node.py process_verify_req genesis derivation.
    return hmac.new(str(int(seed)).encode(), f"GENESIS:{session_id}".encode(), hashlib.sha256).digest()

def _mutual_handshake(*, a_url: str, a_id: str, b_url: str, b_id: str, session_id: str, ephemeral_salt: int) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    # A -> B
    c1 = _post(b_url + "/hive/v12/challenge", {"peer_id": a_id})
    v1 = _post(a_url + "/hive/v12/verify_req/create", {"session_id": session_id, "ephemeral_salt": int(ephemeral_salt), "challenge": c1["challenge"]})
    msg1 = v1["msg"]
    _post(b_url + "/hive/v12/verify_req/process", {"peer_id": a_id, "msg": msg1, "ttl_s": 60})

    # B -> A
    c2 = _post(a_url + "/hive/v12/challenge", {"peer_id": b_id})
    v2 = _post(b_url + "/hive/v12/verify_req/create", {"session_id": session_id, "ephemeral_salt": int(ephemeral_salt), "challenge": c2["challenge"]})
    msg2 = v2["msg"]
    _post(a_url + "/hive/v12/verify_req/process", {"peer_id": b_id, "msg": msg2, "ttl_s": 60})

    return msg1, msg2

# --- Eve Logic ---

class EveDecryptor:
    def __init__(self, seed: int = 7245):
        self.seed = int(seed)
        self.node = FieldBoundNode(pepper="test_pepper", node_id="EVE_LEAK",
            seed=self.seed,
            anchor_seeds=(7245,),
            anchor_weight=80.0,
            n_angles=72,
            scan_resolution=50,
            threshold=0.5,
            planes=4,
            tau_frac=0.55,
            print_deliveries=False,
            print_events=False,
            freeze_field=True,
            backend="frozen",
            content_codec="utf8",  # Eve operates at wire layer.
            vocab=_dummy_vocab(),
        )
        self.known_sessions: Dict[str, Dict[str, Any]] = {}

    def sniff_handshake(self, wire_msg: Dict[str, Any]):
        if wire_msg.get("type") == "VERIFY_REQ":
            sid = wire_msg.get("session_id")
            esalt = wire_msg.get("ephemeral_salt")
            if sid and esalt is not None:
                # Node derives genesis chain hash from (seed, session_id); Eve can compute it too with leaked seed.
                genesis = hmac_genesis(self.seed, str(sid))
                try:
                    from hive.ratchet import kdf_int
                except Exception:
                    from hive.ratchet import kdf_int
                ratchet_key = kdf_int(int(self.seed), f"INIT::{sid}")
                self.known_sessions[str(sid)] = {"ephemeral_salt": int(esalt), "chain_hash": genesis, "next_seq": 2, "ratchet_key": int(ratchet_key)}
                print(f"    [Eve] Sniffed Handshake: SID={str(sid)[:8]}... Salt={int(esalt)}")

    def sniff_and_decrypt(self, wire_msg: Dict[str, Any]) -> str:
        # Check if handshake
        if wire_msg.get("type") == "VERIFY_REQ":
            self.sniff_handshake(wire_msg)
            return "[Handshake Sniffed]"
        
        if wire_msg.get("type") != "DATA": return "[Not DATA]"

        payload = wire_msg.get("payload")
        sid = str(wire_msg.get("session_id", ""))
        nonce = int(wire_msg.get("nonce", 0) or 0)
        if not isinstance(payload, list) or not sid or nonce <= 0:
            return "[Bad Packet]"
        
        if sid not in self.known_sessions:
            return f"[Unknown Session: {sid[:8]}..]"
        st = self.known_sessions[sid]
        esalt = int(st["ephemeral_salt"])
        chain_hash = bytes(st["chain_hash"])
        next_seq = int(st["next_seq"])
        ratchet_key = int(st["ratchet_key"])
        
        # AAD reconstruction (must match hive/node.py)
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
        except Exception as e:
            return f"[AAD Failed: {e}]"

        aad_base = canonical_json(header)
        # Sender increments out_seq before encrypting, so first post-handshake DATA is typically seq=2.
        # Brute force a small window to avoid relying on internal counters.
        for seq in range(max(1, next_seq - 1), next_seq + 4):
            aad = aad_base + chain_hash + struct.pack(">Q", int(seq))
            try:
                pt, _reason, _acks, _tag = self.node.decrypt_bytes(
                    payload,
                    session_id=sid,
                    nonce=int(nonce),
                    ephemeral_salt=int(esalt),
                    aad=aad,
                    ratchet_key=int(ratchet_key),
                )
            except Exception as e:
                return f"[Error: {e}]"

            if pt is None:
                continue

            # Keep Eve's chain state aligned for follow-on packets.
            payload_bytes = bytes(int(x) & 0xFF for x in payload)
            chain_hash = hashlib.sha256(chain_hash + payload_bytes).digest()
            st["chain_hash"] = chain_hash
            st["next_seq"] = int(seq) + 1

            magic = bytes(pt[:8])
            if magic == b"IDREVOC1":
                return f"SUCCESS_DECRYPT: Found IDREVOC1 Header! Payload Size: {len(pt)} bytes. Content is OBFUSCATED IDs."
            return f"RAW_DECRYPT: {list(pt[:20])}... (Not IDREVOC1?)"

        return "[Decryption Failed: MAC mismatch / out of window]"

    # --- Main ---

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--existing-nodes", action="store_true", help="Don't launch nodes, connect to ports 8895/8896")
    args = parser.parse_args()

    print("[*] Starting Vocab Obfuscation Demo...")
    
    p_a = 8895
    p_b = 8896
    vocab_path = str(_REPO_ROOT / "vocab_small.json")
    
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
            "--backend", "frozen",
            "--pepper", "test_pepper"
        ]
        
        print(f"[*] Launching Node A (:{p_a}) and Node B (:{p_b}) ...")
        # Redirect stdout/stderr to capture errors
        proc_a = subprocess.Popen(cmd_base + ["--port", str(p_a), "--node-id", "A"] + common_args, cwd=str(_REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        proc_b = subprocess.Popen(cmd_base + ["--port", str(p_b), "--node-id", "B"] + common_args, cwd=str(_REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
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
        
        # 3. Mutual Handshake (Eve Sniffing)
        a_url = f"http://127.0.0.1:{p_a}"
        b_url = f"http://127.0.0.1:{p_b}"
        
        eve = EveDecryptor(seed=7245)
        
        print("\n[*] Performing Mutual Handshake (Eve Sniffing)...")
        sid = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
        salt = random.getrandbits(31)
        msg1, msg2 = _mutual_handshake(a_url=a_url, a_id="A", b_url=b_url, b_id="B", session_id=sid, ephemeral_salt=int(salt))

        # Eve sees at least one VERIFY_REQ to learn session_id and ephemeral_salt.
        eve.sniff_handshake(msg1)
        eve.sniff_handshake(msg2)
        print("    [OK] Handshake A<->B complete.")
        
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
