#!/usr/bin/env python3
import time
import subprocess
import requests
import sys
import random
import string

# Add repo root to sys.path
from pathlib import Path

# Config
PORT_A = 8910
PORT_B = 8911
PORT_EVE = 8912  # Replay-Clone Eve
SEED = 7245
NODE_CMD = [sys.executable, "scripts/hive_v12_node_server.py"]

def wait_for_port(port, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with requests.get(f"http://127.0.0.1:{port}/health", timeout=1) as r:
                if r.status_code == 200:
                    return True
        except:
            time.sleep(0.5)
    return False

def _post(url, data):
    return requests.post(url, json=data).json()

def run_test():
    # 1. Start Nodes
    # A and B: Lattice + Plasticity
    common_args = [
        "--seed", str(SEED),
        "--planes", "4",
        "--backend", "lattice",
        "--enable-plasticity",
        "--print-events",
        "--pepper", "test_pepper"
    ]
    
    print("[*] Starting Nodes A, B, and Eve (Clone)...")
    proc_a = subprocess.Popen(NODE_CMD + ["--port", str(PORT_A), "--node-id", "A"] + common_args)
    proc_b = subprocess.Popen(NODE_CMD + ["--port", str(PORT_B), "--node-id", "B"] + common_args)
    # EVE: Impersonates B (Clone Attack)
    proc_e = subprocess.Popen(NODE_CMD + ["--port", str(PORT_EVE), "--node-id", "B"] + common_args)
    
    try:
        if not all([wait_for_port(p, timeout=20) for p in [PORT_A, PORT_B, PORT_EVE]]):
            print("[!] Failed to start nodes.")
            # Print status
            for name, pc in [("A", proc_a), ("B", proc_b), ("EVE", proc_e)]:
                if pc.poll() is not None:
                     print(f"[!] {name} crashed with code {pc.returncode}")
            return

        url_a = f"http://127.0.0.1:{PORT_A}"
        url_b = f"http://127.0.0.1:{PORT_B}"
        url_e = f"http://127.0.0.1:{PORT_EVE}"

        # 2. Handshake A <-> B
        print("[*] Handshake A <-> B...")
        
        # A asks B for a challenge
        # B is running on PORT_B.
        b_chal_resp = _post(url_b + "/hive/v12/challenge", {"peer_id": "A"})
        challenge_from_b = b_chal_resp["challenge"]
        print(f"    B issued challenge: {challenge_from_b}")
        
        # A creates response (and inits session locally) using B's challenge
        # Note: A sends to B, so A is the user, B is the service.
        req_a = _post(url_a + "/hive/v12/verify_req/create", {
            "session_id": "SESS_AB", 
            "ephemeral_salt": 1111, 
            "challenge": challenge_from_b
        })
        msg_a = req_a["msg"]
        
        # A sends VerifyReq to B (B inits session)
        resp_verify = _post(url_b + "/hive/v12/verify_req/process", {
            "peer_id": "A", 
            "msg": msg_a, 
            "ttl_s": 300
        })
        
        if not resp_verify.get("verified"):
             print(f"[!] B failed to verify A: {resp_verify}")
             return

        print("[*] Session Established A -> B (on B).")
        
        # FIX: A needs to know about the session too!
        # In this simplified one-way handshake, A didn't automatically create a session.
        # We force it on A to match.
        _post(url_a + "/hive/v12/debug/force_session", {
            "peer_id": "B", 
            "session_id": "SESS_AB",
            "ephemeral_salt": 1111
        })
        print("[*] Forced Session 'B' on Node A.")
        
        # EVE: Force Session (Simulate Perfect Clone / Session Theft)
        # Why?
        # A normal handshake involves a random challenge from B. Eve cannot respond to B's challenge
        # unless she actively MITMs the connection (which changes the session ID).
        # To test "Replay vs Clone" in its purest form ("State-Bound Secrecy"), we skip the handshake attack
        # and GRANT Eve the session state directly. This asks: "Even if Eve steals the session keys, can she keep up?"
        _post(url_e + "/hive/v12/debug/force_session", {
            "peer_id": "A", 
            "session_id": "SESS_AB",
            "ephemeral_salt": 1111
        })
        print("[*] Eve Forced Session 'A'.")
        
        # 3. Drift Phase (Replay Attack)
        print("[*] Starting Drift Phase (50 Messages)...")
        
        for i in range(50):
            # Check if anyone died
            for name, pc in [("A", proc_a), ("B", proc_b), ("EVE", proc_e)]:
                if pc.poll() is not None:
                     print(f"[!] {name} died unexpectedly! Code: {pc.returncode}")
                     return

            # A sends to B
            content = f"Message_{i:04d}_" + "".join(random.choices(string.ascii_letters, k=20))
            
            # 1. A sends message (Updates A's state)
            resp_a = requests.post(
                url_a + "/hive/v12/send_wire", 
                json={
                    "dst_node_id": "B", 
                    "content": content,
                    "prev_hop_id": "A" # Make A wrap it in a ReceiveEnvelope
                }
            )
            if resp_a.status_code != 200:
                print(f"[!] A failed to send msg {i}: {resp_a.text}")
                break
            
            wire_blob = resp_a.content  # The encrypted packet
            
            # 2. B receives message (Updates B's state)
            resp_b = requests.post(
                url_b + "/hive/v12/receive_wire",
                data=wire_blob
            )
            if resp_b.json().get("result", {}).get("status") != "delivered":
                 print(f"[!] B reject msg {i}: {resp_b.text}")
                 print(f"    Reason: {resp_b.json().get('result', {}).get('reason')}")
                 break
            
            # 3. EVE REPLAYS (Updates Eve's state)
            resp_e = requests.post(
                url_e + "/hive/v12/receive_wire",
                data=wire_blob
            )
            
            try:
                r_json = resp_e.json()
                if "error" in r_json:
                     print(f"[!] Eve Error: {r_json['error']}")
                     result_obj = {}
                else:
                     result_obj = r_json.get("result") or {}
            except:
                print(f"[!] Eve Bad JSON: {resp_e.text}")
                result_obj = {}

            status_e = result_obj.get("status")
            
            if status_e == "delivered":
                # Eve Successfully Decrypted and Updated!
                if i % 10 == 0:
                    print(f"    [Eve] Msg {i} Decrypted & Replayed (Sync OK)")
            else:
                print(f"    [Eve] Msg {i} FAILED: {status_e}")
                print(f"    Reason: {result_obj.get('reason')}")
                print(f"    Full Resp: {resp_e.text}")
                print(f"[!] Eve lost sync at message {i}!")
                return # Exit early on failure

        print("[*] Replay Phase Complete.")
        
        # 4. Final Verification
        print("[*] Sending Final Message...")
        final_content = "FINAL_SECRET_PAYLOAD_XYZ"
        resp_a = requests.post(url_a + "/hive/v12/send_wire", json={
            "dst_node_id": "B", 
            "content": final_content,
            "prev_hop_id": "A" # Wrap in ReceiveEnvelope so Eve can ingest it!
        })
        wire_blob = resp_a.content
        
        resp_e = requests.post(url_e + "/hive/v12/receive_wire", data=wire_blob)
        result = resp_e.json().get("result", {})
        
        if not result or result.get("status") != "delivered":
            print("\n[***] EVE FAILED [***]")
            print(f"Eve lost sync! Status: {result.get('status')} Reason: {result.get('reason')}")
            print(f"Raw Result: {resp_e.text}")
            print("The system exhibits CHAOTIC DRIFT (or Forward Secrecy).")
        else:
            print("\n[!!!] EVE SUCCEEDED [!!!]")
            print("Eve successfully maintained sync via Replay-Clone.")
            print("The system is DETERMINISTIC under Full-Take scenarios.")

    finally:
        proc_a.terminate()
        proc_b.terminate()
        proc_e.terminate()
        proc_a.wait()
        proc_b.wait()
        proc_e.wait()

if __name__ == "__main__":
    run_test()
