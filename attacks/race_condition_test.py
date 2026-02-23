#!/usr/bin/env python3
import time
import subprocess
import requests
import sys
import concurrent.futures
import threading

from pathlib import Path

_REPO_PARENT = str(Path(__file__).resolve().parents[1])
if _REPO_PARENT not in sys.path:
    sys.path.insert(0, _REPO_PARENT)

PORT_A = 8920
PORT_B = 8921
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

def run_race_test():
    common_args = [
        "--seed", str(SEED),
        "--planes", "4",
        "--backend", "lattice",
        "--enable-plasticity",
        "--pepper", "test_pepper",
        # Set rate limits high just in case we hit them instead of the logic
        "--rl-verify-rps", "100",
        "--rl-verify-burst", "100",
        "--rl-challenge-rps", "100",
        "--rl-challenge-burst", "100",
    ]
    
    print("[*] Starting Node A and Node B locally for race test...")
    proc_a = subprocess.Popen(NODE_CMD + ["--port", str(PORT_A), "--node-id", "A"] + common_args, stdout=subprocess.DEVNULL)
    proc_b = subprocess.Popen(NODE_CMD + ["--port", str(PORT_B), "--node-id", "B"] + common_args, stdout=subprocess.DEVNULL)
    
    try:
        if not all([wait_for_port(p, timeout=20) for p in [PORT_A, PORT_B]]):
            print("[!] Failed to start nodes.")
            return

        url_a = f"http://127.0.0.1:{PORT_A}"
        url_b = f"http://127.0.0.1:{PORT_B}"

        print("[*] Requesting Challenge from B...")
        resp_b_chal = requests.post(url_b + "/hive/v12/challenge", json={"peer_id": "A"}).json()
        chal = resp_b_chal.get("challenge")
        
        if not chal:
            print("[!] Failed to get challenge from B:", resp_b_chal)
            return

        print("[*] Node A creating VerifyReq...")
        resp_a_req = requests.post(url_a + "/hive/v12/verify_req/create", json={
            "session_id": "RACE_SESSION_123",
            "ephemeral_salt": 12345,
            "challenge": chal
        }).json()
        
        msg = resp_a_req.get("msg")
        if not msg:
            print("[!] Failed to create verify req:", resp_a_req)
            return

        print("[*] Submitting VerifyReq to B with 20 concurrent threads...")
        
        successes = 0
        failures = 0
        
        def submit_verify():
            r = requests.post(url_b + "/hive/v12/verify_req/process", json={
                "peer_id": "A",
                "msg": msg,
                "ttl_s": 300
            })
            return r.status_code, r.json()

        # We intentionally use a barrier to align threads to hit the server at the exact same moment
        num_threads = 20
        barrier = threading.Barrier(num_threads)
        
        def align_and_submit():
            barrier.wait()
            return submit_verify()

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(align_and_submit) for _ in range(num_threads)]
            for f in concurrent.futures.as_completed(futures):
                try:
                    status, json_resp = f.result()
                    if status == 200 and json_resp.get("verified") is True:
                        successes += 1
                    else:
                        failures += 1
                except Exception as e:
                    failures += 1
                    print(f"Exception: {e}")

        print(f"\n[*] Results: Successes (Accepted) = {successes}, Failures (Rejected) = {failures}")
        if successes == 1 and failures == num_threads - 1:
            print("[SUCCESS] Race condition mitigated! Exactly ONE request was accepted.")
        elif successes > 1:
            print("[FAIL] Race condition detected! Multiple identical VERIFY_REQ accepted.")
        elif successes == 0:
            print("[FAIL] All requests were rejected!")

    finally:
        proc_a.terminate()
        proc_b.terminate()
        proc_a.wait()
        proc_b.wait()

if __name__ == "__main__":
    run_race_test()
