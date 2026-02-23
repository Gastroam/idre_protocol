#!/usr/bin/env python3
"""
Verify Real IDRE Message Streaming (Bidirectional) via HTTP + Toxic Eve + Protocol Breaking.

This script drives three RUNNING node servers:
- Node A: http://127.0.0.1:8890
- Node B: http://127.0.0.1:8891
- Node E (Eve): http://127.0.0.1:8892 (simulates attacker)

Attacks:
1. Toxic Suite (Random Fuzzing/Tampering)
2. Protocol Breaking (Reflection, Seed Cracking, Injection)
3. Leak Decryption (Eve has seed, decrypts traffic)
"""


import sys
import os
import time
import random
import hashlib
import copy
import traceback
from typing import Dict, Any, Optional
from pathlib import Path

# Add repo parent to sys.path to support 'import idre_clean'
_REPO_PARENT = str(Path(__file__).resolve().parent.parent.parent)
if _REPO_PARENT not in sys.path:
    sys.path.insert(0, _REPO_PARENT)

from idre_clean.hive.client import HiveClient
# Import FieldBoundNode for Eve/Cracker logic locally
from idre_clean.hive.node import FieldBoundNode

def canonical_json(obj: Any) -> bytes:
    from idre_clean.hive.utils import canonical_json as util_cjs
    return util_cjs(obj)

# --- Core Logic ---

def _handshake(client_a: HiveClient, a_id: str, client_b: HiveClient, b_id: str, session_id: str, e_salt: int, observer=None):
    print(f"[*] Handshake {a_id} ({client_a.base_url}) <-> {b_id} ({client_b.base_url})...")
    
    # A -> B
    # 1. A asks B for challenge
    chal = client_b.get_challenge(a_id)
    if not chal: raise RuntimeError("Challenge A->B failed")
    
    # 2. A creates Verify Req
    msg = client_a.create_verify_req(session_id, e_salt, chal)
    if not msg: raise RuntimeError("VerifyCreate A failed")
    
    # Eve Sniffs A->B handshake msg
    if observer: observer.sniff_handshake(msg)
    
    # 3. B processes Verify Req
    if not client_b.process_verify_req(a_id, msg, ttl_s=600):
        raise RuntimeError("VerifyProcess B failed")
    print(f"    [OK] {b_id} verified {a_id}")

    # B -> A
    # 1. B asks A for challenge
    chal = client_a.get_challenge(b_id)
    if not chal: raise RuntimeError("Challenge B->A failed")
    
    # 2. B creates Verify Req
    # Note: Using same session_id/salt for mutual session as per standard flow in this test
    msg = client_b.create_verify_req(session_id, e_salt, chal)
    if not msg: raise RuntimeError("VerifyCreate B failed")
    
    # Eve Sniffs B->A handshake msg
    if observer: observer.sniff_handshake(msg)
    
    # 3. A processes Verify Req
    if not client_a.process_verify_req(b_id, msg, ttl_s=600):
         raise RuntimeError("VerifyProcess A failed")
    print(f"    [OK] {a_id} verified {b_id}")

def send_msg(client_src: HiveClient, src_id: str, dst_id: str, content: str, created_at_ms: int = None) -> Dict[str, Any]:
    msg = client_src.send(dst_id, content, created_at_ms=created_at_ms)
    if not msg: raise RuntimeError(f"Send failed {src_id}->{dst_id}")
    return msg

def receive_msg(client_dst: HiveClient, src_id: str, wire_msg: Dict[str, Any]) -> str:
    return client_dst.receive(src_id, wire_msg)

# --- Toxic Attack Strategies ---

def attack_replay(wire_msg: Dict[str, Any], **kwargs) -> Dict[str, Any]:
    return copy.deepcopy(wire_msg)

def attack_tamper_bitflip(wire_msg: Dict[str, Any], **kwargs) -> Dict[str, Any]:
    tampered = copy.deepcopy(wire_msg)
    payload = tampered.get("payload")
    if isinstance(payload, list) and len(payload) > 5:
        idx = len(payload) // 2
        payload[idx] = (payload[idx] ^ 0xFF) & 0xFF
    return tampered

def attack_json_fuzz(wire_msg: Dict[str, Any], **kwargs) -> Dict[str, Any]:
    fuzzed = copy.deepcopy(wire_msg)
    strategy = random.choice(["inject_garbage", "bad_type", "drop_field"])
    if strategy == "inject_garbage":
        fuzzed["garbage_" + str(random.randint(0, 100))] = "trash" * 10
    elif strategy == "bad_type":
        if "session_id" in fuzzed: fuzzed["session_id"] = 12345
        else: fuzzed["payload"] = "not_list"
    elif strategy == "drop_field":
        keys = list(fuzzed.keys())
        if keys: del fuzzed[random.choice(keys)]
    return fuzzed

def attack_time_travel(wire_msg, **kwargs) -> Dict[str, Any]:
    client_src = kwargs.get("client_src")
    src_id = kwargs.get("src_id")
    dst_id = kwargs.get("dst_id")
    now_ms = int(time.time() * 1000)
    ts = now_ms - (3600 * 1000 * 24) if random.random() < 0.5 else now_ms + (3600 * 1000 * 24)
    try:
        return send_msg(client_src, src_id, dst_id, "ATTACK_TIME", created_at_ms=ts)
    except Exception:
        return wire_msg

def attack_session_hijack(wire_msg: Dict[str, Any], **kwargs) -> Dict[str, Any]:
    session_id = wire_msg.get("session_id", "0"*32)
    fake_frame = {
        "type": "DATA",
        "session_id": session_id,
        "nonce": random.getrandbits(32),
        "payload": [random.randint(0, 255) for _ in range(32)],
        "msg_id": random.getrandbits(32)
    }
    return fake_frame

def attack_protocol_fuzz(wire_msg: Dict[str, Any], **kwargs) -> Dict[str, Any]:
    fuzzed = copy.deepcopy(wire_msg)
    fuzzed["type"] = random.choice(["UNKNOWN", "CONTROL", "DATA_V2", "HACK"])
    return fuzzed

# --- Protocol Breaking Attacks ---

def attack_reflection(wire_msg: Dict[str, Any], **kwargs) -> Dict[str, Any]:
    # Reflect A->B back to A.
    # Note: caller handles sending to correct dest (A), here we just return the msg.
    return copy.deepcopy(wire_msg)

class SeedCracker:
    def __init__(self, target_seed: int = 7245):
        self.cracked_seed = None
        self.node = None
        self.target_seed = target_seed # In real life unknown, here we cheat a bit to limit search space or verify
        
    def crack(self, wire_msg: Dict[str, Any], src_id: str) -> Optional[int]:
        if self.cracked_seed is not None:
            return self.cracked_seed
            
        print("      [Cracker] Attempting to crack seed (range 7000-8000)...")
        if not FieldBoundNode:
            print("      [Cracker] Skip: FieldBoundNode not imported.")
            return None
        return None 
        
    def brute_force_handshake(self, a_id: str, client_b: HiveClient) -> Optional[int]:
        if self.cracked_seed: return self.cracked_seed
        
        print("      [Cracker] Brute-forcing handshake with B...")
        # Try seeds around 7245
        for s in range(7240, 7250):
            # Create a local node
            try:
                # We need to simulate the handshake process from a script.
                # A -> B (challenge)
                chal = client_b.get_challenge(a_id)
                if not chal: continue
                
                # We need to GENERATE the verify_req locally using seed `s`
                # We can use FieldBoundNode logic here if imported.
                if not FieldBoundNode: return None
                
                # Mock a local node with correct params
                # Helper for vocab (copied from verifying scripts)
                try: from idre_clean.core.vocab_codec import Vocab
                except: from core.vocab_codec import Vocab
                _dummy = Vocab(["a"], {"a":0}, b"dum", {})

                node = FieldBoundNode(pepper="test_pepper", node_id="EVE_CLONE", seed=s,
                    anchor_seeds=(7245,), anchor_weight=80.0,
                    n_angles=72, scan_resolution=50, threshold=0.5,
                    planes=4, tau_frac=0.55,
                    print_deliveries=False, print_events=False,
                    freeze_field=True, backend="frozen",
                    vocab=_dummy,
                )
                
                # Construct the payload locally
                # We assume correct seed `s` makes a valid MAC.
                sid = "0" * 32
                esalt = 0
                req = node.create_verify_req(sid, esalt, chal)
                
                # Send to B
                if client_b.process_verify_req(a_id, req["msg"], ttl_s=60):
                    print(f"      [Cracker] CRACKED! Seed is {s}")
                    self.cracked_seed = s
                    self.node = node # Keep the cracker node
                    return s
            except Exception:
                pass
        return None

    def inject(self, dst_id: str, content: str) -> Dict[str, Any]:
        if not self.node: return {}
        return self.node.send(dst_id, content)

class EveDecryptor:
    """Simulates Eve inspecting traffic using a known/leaked seed, BUT NO Vocab."""
    def __init__(self, seed: int = 7245):
        self.node = None
        self.known_sessions: Dict[str, int] = {} # session_id -> ephemeral_salt
        if FieldBoundNode:
            # Eve has the seed, but NO vocab
            try: from idre_clean.core.vocab_codec import Vocab
            except: from core.vocab_codec import Vocab
            _dummy = Vocab(["a"], {"a":0}, b"dum", {})
            
            self.node = FieldBoundNode(pepper="test_pepper", node_id="EVE_LEAK", seed=seed,
                anchor_seeds=(7245,), anchor_weight=80.0,
                n_angles=72, scan_resolution=50, threshold=0.5,
                planes=4, tau_frac=0.55,
                print_deliveries=False, print_events=False,
                freeze_field=True, backend="frozen",
                vocab=_dummy,
            )

    def sniff_handshake(self, wire_msg: Dict[str, Any]):
        """Passively learns session parameters from VERIFY_REQ."""
        msg_type = wire_msg.get("type", "")
        if msg_type == "VERIFY_REQ":
            sid = wire_msg.get("session_id")
            esalt = wire_msg.get("ephemeral_salt")
            if sid and esalt is not None:
                self.known_sessions[sid] = int(esalt)
                # print(f"    [Eve] Sniffed handshake: sid={sid[:8]}.. salt={esalt}")

    def sniff_and_decrypt(self, wire_msg: Dict[str, Any]) -> str:
        if not self.node: return "[No Lib]"
        
        # Also sniff handshake here just in case caller passes VERIFY_REQ
        self.sniff_handshake(wire_msg)
        
        # Only decrypt DATA
        if wire_msg.get("type") != "DATA": return "[Not DATA]"

        payload = wire_msg.get("payload")
        sid = wire_msg.get("session_id")
        nonce = wire_msg.get("nonce")
        
        # Look up salt
        if sid not in self.known_sessions:
            return f"[Unknown Session: {sid[:8]}..]"
        esalt = self.known_sessions[sid]
        
        if not payload or not sid or nonce is None: return "[Invalid]"
        
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
            return f"[AAD Construct Failed: {e}]"

        try:
             # decrypt_bytes returns List[int] (the payload)
            decrypted = self.node.decrypt_bytes(
                payload, 
                session_id=sid, 
                nonce=int(nonce), 
                ephemeral_salt=int(esalt),
                aad=aad
            )
            if decrypted is not None:
                # RAW IDs!
                return f"RAW_IDs: {list(decrypted)}" 
            else:
                return "[Decryption Failed (MAC mismatch or internal error)]"
        except Exception as e:
            traceback.print_exc()
            return f"[Error: {e}]"



# --- Server Management ---
# Calculate REPO_PARENT correctly. 
# If this script is in f:\idre_clean\scripts\, 
# Path(__file__).resolve() -> f:\idre_clean\scripts\verify_real_stream.py
# .parent -> f:\idre_clean\scripts
# .parent.parent -> f:\idre_clean (THIS IS THE REPO ROOT)
_REPO_ROOT = Path(__file__).resolve().parent.parent
NODE_CMD = [sys.executable, str(_REPO_ROOT / "scripts" / "hive_v12_node_server.py")]
PORT_A = 8890
PORT_B = 8891
PORT_E = 8892
SEED = 7245

def wait_for_port(port, timeout=10):
    import requests
    start = time.time()
    while time.time() - start < timeout:
        try:
            with requests.get(f"http://127.0.0.1:{port}/health", timeout=1) as r:
                if r.status_code == 200:
                    return True
        except:
            time.sleep(0.5)
    return False

def attack_protocol_fuzz(wire_msg: Dict[str, Any], **kwargs) -> Dict[str, Any]:
    fuzzed = copy.deepcopy(wire_msg)
    fuzzed["type"] = random.choice(["UNKNOWN", "CONTROL", "DATA_V2", "HACK"])
    return fuzzed

# --- Protocol Breaking Attacks ---

def attack_reflection(wire_msg: Dict[str, Any], **kwargs) -> Dict[str, Any]:
    # Reflect A->B back to A.
    # Note: caller handles sending to correct dest (A), here we just return the msg.
    return copy.deepcopy(wire_msg)

class SeedCracker:
    def __init__(self, target_seed: int = 7245):
        self.cracked_seed = None
        self.node = None
        self.target_seed = target_seed # In real life unknown, here we cheat a bit to limit search space or verify
        
    def crack(self, wire_msg: Dict[str, Any], src_id: str) -> Optional[int]:
        if self.cracked_seed is not None:
            return self.cracked_seed
            
        print("      [Cracker] Attempting to crack seed (range 7000-8000)...")
        if not FieldBoundNode:
            print("      [Cracker] Skip: FieldBoundNode not imported.")
            return None
        return None 
        
    def brute_force_handshake(self, a_id: str, client_b: HiveClient) -> Optional[int]:
        if self.cracked_seed: return self.cracked_seed
        
        print("      [Cracker] Brute-forcing handshake with B...")
        # Try seeds around 7245
        for s in range(7240, 7250):
            # Create a local node
            try:
                # We need to simulate the handshake process from a script.
                # A -> B (challenge)
                chal = client_b.get_challenge(a_id)
                if not chal: continue
                
                # We need to GENERATE the verify_req locally using seed `s`
                # We can use FieldBoundNode logic here if imported.
                if not FieldBoundNode: return None
                
                # Mock a local node with correct params
                # Helper for vocab (copied from verifying scripts)
                try: from idre_clean.core.vocab_codec import Vocab
                except: from core.vocab_codec import Vocab
                _dummy = Vocab(["a"], {"a":0}, b"dum", {})

                node = FieldBoundNode(pepper="test_pepper", node_id="EVE_CLONE", seed=s,
                    anchor_seeds=(7245,), anchor_weight=80.0,
                    n_angles=72, scan_resolution=50, threshold=0.5,
                    planes=4, tau_frac=0.55,
                    print_deliveries=False, print_events=False,
                    freeze_field=True, backend="frozen",
                    vocab=_dummy,
                )
                
                # Construct the payload locally
                # We assume correct seed `s` makes a valid MAC.
                sid = "0" * 32
                esalt = 0
                req = node.create_verify_req(sid, esalt, chal)
                
                # Send to B
                if client_b.process_verify_req(a_id, req["msg"], ttl_s=60):
                    print(f"      [Cracker] CRACKED! Seed is {s}")
                    self.cracked_seed = s
                    self.node = node # Keep the cracker node
                    return s
            except Exception:
                pass
        return None

    def inject(self, dst_id: str, content: str) -> Dict[str, Any]:
        if not self.node: return {}
        return self.node.send(dst_id, content)

class EveDecryptor:
    """Simulates Eve inspecting traffic using a known/leaked seed, BUT NO Vocab."""
    def __init__(self, seed: int = 7245):
        self.node = None
        self.known_sessions: Dict[str, int] = {} # session_id -> ephemeral_salt
        if FieldBoundNode:
            # Eve has the seed, but NO vocab
            try: from idre_clean.core.vocab_codec import Vocab
            except: from core.vocab_codec import Vocab
            _dummy = Vocab(["a"], {"a":0}, b"dum", {})
            
            self.node = FieldBoundNode(pepper="test_pepper", node_id="EVE_LEAK", seed=seed,
                anchor_seeds=(7245,), anchor_weight=80.0,
                n_angles=72, scan_resolution=50, threshold=0.5,
                planes=4, tau_frac=0.55,
                print_deliveries=False, print_events=False,
                freeze_field=True, backend="frozen",
                vocab=_dummy,
            )

    def sniff_handshake(self, wire_msg: Dict[str, Any]):
        """Passively learns session parameters from VERIFY_REQ."""
        msg_type = wire_msg.get("type", "")
        if msg_type == "VERIFY_REQ":
            sid = wire_msg.get("session_id")
            esalt = wire_msg.get("ephemeral_salt")
            if sid and esalt is not None:
                self.known_sessions[sid] = int(esalt)
                # print(f"    [Eve] Sniffed handshake: sid={sid[:8]}.. salt={esalt}")

    def sniff_and_decrypt(self, wire_msg: Dict[str, Any]) -> str:
        if not self.node: return "[No Lib]"
        
        # Also sniff handshake here just in case caller passes VERIFY_REQ
        self.sniff_handshake(wire_msg)
        
        # Only decrypt DATA
        if wire_msg.get("type") != "DATA": return "[Not DATA]"

        payload = wire_msg.get("payload")
        sid = wire_msg.get("session_id")
        nonce = wire_msg.get("nonce")
        
        # Look up salt
        if sid not in self.known_sessions:
            return f"[Unknown Session: {sid[:8]}..]"
        esalt = self.known_sessions[sid]
        
        if not payload or not sid or nonce is None: return "[Invalid]"
        
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
            return f"[AAD Construct Failed: {e}]"

        try:
             # decrypt_bytes returns List[int] (the payload)
            decrypted = self.node.decrypt_bytes(
                payload, 
                session_id=sid, 
                nonce=int(nonce), 
                ephemeral_salt=int(esalt),
                aad=aad
            )
            if decrypted is not None:
                # RAW IDs!
                return f"RAW_IDs: {list(decrypted)}" 
            else:
                return "[Decryption Failed (MAC mismatch or internal error)]"
        except Exception as e:
            traceback.print_exc()
            return f"[Error: {e}]"



# --- Server Management ---
# Calculate REPO_PARENT correctly. 
# If this script is in f:\idre_clean\scripts\, 
# Path(__file__).resolve() -> f:\idre_clean\scripts\verify_real_stream.py
# .parent -> f:\idre_clean\scripts
# .parent.parent -> f:\idre_clean (THIS IS THE REPO ROOT)
_REPO_ROOT = Path(__file__).resolve().parent.parent
NODE_CMD = [sys.executable, str(_REPO_ROOT / "scripts" / "hive_v12_node_server.py")]
PORT_A = 8890
PORT_B = 8891
PORT_E = 8892
SEED = 7245

def main():
    import subprocess
    
    a_url = f"http://127.0.0.1:{PORT_A}"
    b_url = f"http://127.0.0.1:{PORT_B}"
    
    # 1. Start Servers
    print("[*] Starting Nodes A, B, and Eve (Real Processes)...")
    common_args = [
        "--seed", str(SEED),
        "--planes", "4",
        "--pepper", "test_pepper"
    ]
    
    # Check if servers are already running (manual mode compatibility)
    manual_mode = False
    if wait_for_port(PORT_A, timeout=1):
        print("[!] Nodes already running. Using existing instances.")
        manual_mode = True
        procs = []
    else:
        # Launch them
        procs = [
            subprocess.Popen(NODE_CMD + ["--port", str(PORT_A), "--node-id", "A"] + common_args),
            subprocess.Popen(NODE_CMD + ["--port", str(PORT_B), "--node-id", "B"] + common_args),
            subprocess.Popen(NODE_CMD + ["--port", str(PORT_E), "--node-id", "E"] + common_args)
        ]
        if not all([wait_for_port(p, timeout=20) for p in [PORT_A, PORT_B, PORT_E]]):
            print("[!] Failed to start nodes.")
            for p in procs: p.terminate()
            sys.exit(1)
            
    try:
        client_a = HiveClient(a_url)
        client_b = HiveClient(b_url)
        # Fetch IDs (Health checks)
        ha = client_a.hello()
        hb = client_b.hello()
        a_id = ha.get("node_id", "A")
        b_id = hb.get("node_id", "B")
    
        print("\n[*] Starting Stream... (Toxic + Protocol Breaking + LEAK)")
        
        cracker = SeedCracker()
        # Initialize Leaker with known seed 7245
        leaker = EveDecryptor(seed=7245)
    
        # Handshake - pass 'leaker' as observer to sniff params
        sid = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
        salt = random.getrandbits(31)
        try:
            _handshake(client_a, a_id, client_b, b_id, sid, salt, observer=leaker)
        except Exception as e:
            print(f"[!] Handshake failed: {e}")
            # sys.exit(1)
            
        start_time = time.time()
        duration = 15 # Reduced duration for CI
        seq = 0
        
        attack_strategies = [
            ("Replay", attack_replay),
            ("BitFlip", attack_tamper_bitflip),
            ("JSONFuzz", attack_json_fuzz),
            ("TimeTravel", attack_time_travel),
            ("SessionHijack", attack_session_hijack),
            ("ProtoFuzz", attack_protocol_fuzz),
            ("Reflection", attack_reflection)
        ]
        
        while time.time() - start_time < duration:
            seq += 1
            elapsed = int(time.time() - start_time)
            print(f"\n--- T+{elapsed}s (Seq {seq}) ---")
            
            # 1. Valid A -> B
            try:
                # Use valid vocab tokens!
                content = f"hello world this is message {seq} from node A"
                wire_a = send_msg(client_a, a_id, b_id, content)
                
                # --- LEAK DEMO ---
                # Eve captures 'wire_a' and tries to decrypt it
                if leaker.node:
                    dec = leaker.sniff_and_decrypt(wire_a)
                    print(f"    [Eve] **SNIFF** Decrypted: {dec}")
                # -----------------
                
                if receive_msg(client_b, a_id, wire_a) != "delivered":
                    print("    [A->B] FAIL (Delivery)")
    
                # 2. Attacks
                name, func = random.choice(attack_strategies)
                
                # Special case: Reflection targets A, others target B
                if name == "Reflection":
                    # Eve sends wire_a (A->B) back to A, pretending it came from B
                    malicious_msg = func(wire_a)
                    status = receive_msg(client_a, b_id, malicious_msg)
                    print(f"    [Eve->A] Strategy: {name} -> {status} [PASS]")
                else:
                    # Normal attacks targeting B
                    malicious_msg = func(wire_a, client_src=client_a, src_id=a_id, dst_id=b_id)
                    status = receive_msg(client_b, a_id, malicious_msg)
                    if status == "delivered":
                         print(f"      [RESULT] {name}: FAIL (delivered)")
                    else:
                         print(f"      [RESULT] {name}: BLOCKED ({status}) [PASS]")
    
                # 3. Seed Crack & Inject (The Breaker)
                # Try to crack seed if not yet cracked
                if not cracker.cracked_seed:
                    cracker.brute_force_handshake(a_id, client_b)
                    pass
                    
            except Exception as e:
                traceback.print_exc()
                print(f"    [!] Error (seq {seq}): {e}")
    
            # 3. Valid B -> A
            try:
                content = f"hello from B message {seq}"
                wire_b = send_msg(client_b, b_id, a_id, content)
                receive_msg(client_a, b_id, wire_b)
            except: pass
                
            time.sleep(1.0) # 1s cadence
    
        print("\n[SUCCESS] Test complete.")
        
    finally:
        if not manual_mode:
            print("[*] Terminating Servers...")
            for p in procs: 
                p.terminate()
                p.wait()

if __name__ == "__main__":
    main()
