#!/usr/bin/env python3
import time
import subprocess
import requests
import sys
import random
import string

# Add repo root to sys.path
from pathlib import Path

from hive.client import HiveClient

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
    common_args = [
        "--seed", str(SEED),
        "--planes", "4",
        "--backend", "lattice",
        "--enable-plasticity",
        "--print-events",
        "--pepper", "test_pepper"
    ]
    
    print("[*] Starting Nodes A, B, and Eve (Clone)...")
    import os
    env = os.environ.copy()
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env['PYTHONPATH'] = root_dir + (os.pathsep + env['PYTHONPATH'] if 'PYTHONPATH' in env else '')
    proc_a = subprocess.Popen(env=env, cwd=root_dir, NODE_CMD + ["--port", str(PORT_A), "--node-id", "A"] + common_args)
    proc_b = subprocess.Popen(env=env, cwd=root_dir, NODE_CMD + ["--port", str(PORT_B), "--node-id", "B"] + common_args)
    # EVE: Impersonates B (Clone Attack)
    proc_e = subprocess.Popen(env=env, cwd=root_dir, NODE_CMD + ["--port", str(PORT_EVE), "--node-id", "B"] + common_args)
    
    try:
        if not all([wait_for_port(p, timeout=20) for p in [PORT_A, PORT_B, PORT_EVE]]):
            print("[!] Failed to start nodes.")
            return

        url_a = f"http://127.0.0.1:{PORT_A}"
        url_b = f"http://127.0.0.1:{PORT_B}"
        url_e = f"http://127.0.0.1:{PORT_EVE}"

        # 2. Handshake A <-> B
        print("[*] Handshake A <-> B...")
        client_a = HiveClient(url_a)
        client_b = HiveClient(url_b)
        client_e = HiveClient(url_e)
        
        # 2. Handshake A <-> B
        # A asks B for challenge
        chal = client_b.get_challenge("A")
        
        # A creates Verify Req
        msg_a = client_a.create_verify_req(
            "SESS_AB", 1111, chal
        )
        
        # B verifies A
        if not client_b.process_verify_req("A", msg_a, ttl_s=300):
             print("[!] B failed to verify A")
             return

        print("[*] Session Established A -> B (on B).")
        
        # Force Session on A (Still need manual endpoint or client update? HiveClient doesn't support debug endpoints yet)
        # Force Session on A (Still need manual endpoint or client update? HiveClient doesn't support debug endpoints yet)
        # I'll add a raw _post helper for debug endpoints or just use requests directly for debug
        client_a.force_session(
            peer_id="B", 
            session_id="SESS_AB",
            ephemeral_salt=1111
        )
        
        # Force Session on Eve (Clone)
        print("[*] Eve Sniffs Handshake (A->B)...")
        client_e.force_session(
            peer_id="A", 
            session_id="SESS_AB",
            ephemeral_salt=1111
        )
        print("[*] Eve Forced Session 'A'.")
        
        # 3. Drift Phase (Tests Epoch Anchor)
        print("[*] Starting Packet Steam (Anchor Verification)...")
        
        dropper_idx = 10 # Eve drops packet #10
        failed = False
        
        for i in range(20):
            content = f"Message_{i:04d}_" + "".join(random.choices(string.ascii_letters, k=20))
            
            # A sends to B (Client sends via POST /hive/v12/send which returns the 'msg' dict)
            wire_msg = client_a.send("B", content)
            
            if not wire_msg:
                 print(f"[!] A failed to send msg {i}")
                 break
            
            # B receives
            status_b = client_b.receive("A", wire_msg)
            if status_b != "delivered":
                 print(f"[!] B reject msg {i}: {status_b}")
                 break
            
            # EVE REPLAYS
            if i == dropper_idx:
                print(f"[Eve] *DROPPED* Message {i} (Simulating Packet Loss)")
                continue

            status_e = client_e.receive("A", wire_msg)
            
            if i < dropper_idx:
                if status_e != "delivered":
                     print(f"[!] Eve failed EARLY at {i}")
                     return
            
            elif i > dropper_idx:
                # Expect FAILURE immediately after drop
                if status_e == "delivered":
                    print(f"[!] Eve SUCCEEDED at {i} despite missing packet {dropper_idx}!")
                    print("    [!] Epoch Anchor FAILED. Eve should be locked out.")
                    failed = True
                    break
                else:
                    print(f"    [Eve] Msg {i} REJECTED (EXPECTED)")
        
        if not failed:
             print("\n[SUCCESS] Epoch Anchor Verified.")
             print("Eve was instantly locked out after missing 1 packet.")

    finally:
        proc_a.terminate()
        proc_b.terminate()
        proc_e.terminate()
        proc_a.wait()
        proc_b.wait()
        proc_e.wait()

if __name__ == "__main__":
    run_test()
