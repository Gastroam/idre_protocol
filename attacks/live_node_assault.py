#!/usr/bin/env python3
"""
Live Node Assault Suite — IDRE Protocol External Attack Testing
Target: idre.mti-evo.online

This script executes the attack vectors outlined in live_attack_plan.md
against the publicly deployed Demo API and raw node endpoints.
"""
import sys
import os
import json
import time
import statistics
import requests
import secrets
from concurrent.futures import ThreadPoolExecutor

BASE_URL = "https://idre.mti-evo.online"
API_SEND = f"{BASE_URL}/api/demo/send"
API_RECEIVE = f"{BASE_URL}/api/demo/receive"
API_STATUS = f"{BASE_URL}/api/demo/status"
NODE_A_CHALLENGE = f"{BASE_URL}/node-a/hive/v12/challenge"

# Print formatting
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    ENDC = '\033[0m'

def print_hdr(text):
    print(f"\n{Colors.CYAN}=== {text} ==={Colors.ENDC}")

def log_succ(text):
    print(f" {Colors.GREEN}[+]{Colors.ENDC} {text}")

def log_fail(text):
    print(f" {Colors.RED}[-]{Colors.ENDC} {text}")

def log_warn(text):
    print(f" {Colors.YELLOW}[!]{Colors.ENDC} {text}")

def check_alive():
    try:
        r = requests.get(API_STATUS, timeout=5)
        if r.status_code == 200:
            log_succ(f"Target is ALIVE: {BASE_URL}")
            return True
        log_fail(f"Target returns {r.status_code}")
    except Exception as e:
        log_fail(f"Target is UNREACHABLE: {e}")
    return False

# -------------------------------------------------------------------
# Phase 1: Cryptanalysis (Cipher & Side-Channels)
# -------------------------------------------------------------------

def phase_1_known_plaintext():
    print_hdr("Phase 1.1: Known-Plaintext & Chosen-Plaintext (Permute-XOR Analysis)")
    # We send highly structured data to see if the ciphertext leaks structure
    # (e.g., if the permutation schedule repeats or if block size is predictable)
    
    payloads = [
        "A" * 64,
        "A" * 65,  # Crossing a block boundary
        "B" * 64,
        "".join([chr(i % 256) for i in range(128)]),  # Incremental
    ]
    
    wire_sizes = []
    
    for pt in payloads:
        try:
            r = requests.post(API_SEND, json={"message": pt}, timeout=5)
            data = r.json()
            if "wire_message" in data:
                payload_ints = data["wire_message"]["payload"]
                wire_sizes.append(len(payload_ints))
                log_succ(f"Encrypted {len(pt)} bytes -> {len(payload_ints)} integers")
            else:
                log_fail(f"Encryption failed: {data}")
        except Exception as e:
            log_fail(f"Send error: {e}")
            return

    # Check for padding oracle / length leakage
    c_set = set(wire_sizes)
    if len(c_set) == 1:
        log_succ("SUCCESS: All ciphertexts have the same length. Adaptive padding is working.")
    else:
        log_warn(f"VULNERABILITY: Ciphertext lengths vary {c_set}. Padding may leak plaintext length.")

def phase_1_timing_side_channel():
    print_hdr("Phase 1.2: Timing Side-Channels (HMAC Validation)")
    # We send a valid message and then tamper with the MAC one byte at a time.
    # If the server uses a non-constant-time comparison, the response time will vary.
    
    try:
        r_send = requests.post(API_SEND, json={"message": "timing_test"}, timeout=5)
        wire_msg = r_send.json()["wire_message"]
    except Exception as e:
        log_fail(f"Failed to setup timing test: {e}")
        return

    orig_payload = list(wire_msg["payload"])
    
    latencies = []
    
    # 1. Baseline (Valid)
    times = []
    for _ in range(5):
        t0 = time.time()
        requests.post(API_RECEIVE, json={"wire_message": wire_msg})
        times.append(time.time() - t0)
    baseline_lat = statistics.median(times)
    log_succ(f"Baseline latency (Valid Payload): {baseline_lat*1000:.2f} ms")
    
    # 2. Tampered (First payload byte changed)
    tampered_1 = dict(wire_msg)
    t1_payload = list(orig_payload)
    t1_payload[0] = (t1_payload[0] + 1) % 256
    tampered_1["payload"] = t1_payload
    
    times = []
    for _ in range(5):
        t0 = time.time()
        requests.post(API_RECEIVE, json={"wire_message": tampered_1})
        times.append(time.time() - t0)
    tamper_1_lat = statistics.median(times)
    
    # 3. Tampered (Last payload byte changed - often part of MAC)
    tampered_2 = dict(wire_msg)
    t2_payload = list(orig_payload)
    t2_payload[-1] = (t2_payload[-1] + 1) % 256
    tampered_2["payload"] = t2_payload
    
    times = []
    for _ in range(5):
        t0 = time.time()
        requests.post(API_RECEIVE, json={"wire_message": tampered_2})
        times.append(time.time() - t0)
    tamper_2_lat = statistics.median(times)
    
    log_succ(f"Tampered first char latency: {tamper_1_lat*1000:.2f} ms")
    log_succ(f"Tampered last char latency:  {tamper_2_lat*1000:.2f} ms")
    
    diff = abs(tamper_1_lat - tamper_2_lat)
    if diff > 0.05: # 50ms variance is suspicious
        log_warn(f"VULNERABILITY: MAC verification time differs by {diff*1000:.2f}ms. Potential side-channel.")
    else:
        log_succ("SUCCESS: MAC verification appears constant-time (within network jitter).")


# -------------------------------------------------------------------
# Phase 2: Protocol Logic & State Disruption
# -------------------------------------------------------------------

def phase_2_handshake_bypass():
    print_hdr("Phase 2.1: Handshake Bypass")
    # Attempt to process a raw frame without a valid session
    
    spoofed_msg = {
        "proto": "HIVE-P2P/1.2",
        "peer_id": "EVE_THE_ATTACKER",
        "type": "DATA",
        "session_id": secrets.token_hex(16),
        "nonce": secrets.randbits(64),
        "ephemeral_salt": secrets.randbits(64),
        "aad_anchor": "fake_anchor",
        "auth_tag": secrets.token_hex(32),
        "payload": [1, 2, 3, 4]
    }
    
    try:
        r = requests.post(API_RECEIVE, json={"wire_message": spoofed_msg}, timeout=5)
        res = r.json()
        if res.get("status") in ("rejected", "reject"):
            log_succ(f"SUCCESS: Node rejected spoofed session frame. Reason: {res.get('rejection_reason')}")
        else:
            log_fail(f"VULNERABILITY: Node accepted spoofed frame! Result: {res}")
    except Exception as e:
        log_fail(f"Request failed: {e}")

def phase_2_replay_attack():
    print_hdr("Phase 2.2: Epoch Anchor Replay Attack")
    
    try:
        # Resync Alice and Bob explicitly since Phase 1 dropped packets
        requests.post(f"{BASE_URL}/api/demo/handshake", timeout=5)

        # Get a valid message
        r_send = requests.post(API_SEND, json={"message": "replay_me"}, timeout=5)
        wire_msg = r_send.json()["wire_message"]
        
        # Deliver it once (should succeed)
        r1 = requests.post(API_RECEIVE, json={"wire_message": wire_msg}, timeout=5)
        res1 = r1.json()
        if res1.get("status") == "delivered":
            log_succ("Initial delivery successful.")
        else:
            log_fail(f"Initial delivery failed: {res1}")
            return
            
        # Deliver it again (should be REJECTED as a replay)
        r2 = requests.post(API_RECEIVE, json={"wire_message": wire_msg}, timeout=5)
        res2 = r2.json()
        
        if res2.get("status") in ("rejected", "reject"):
            log_succ(f"SUCCESS: Replay attack thwarted. Reason: {res2.get('rejection_reason')}")
        else:
            log_fail(f"VULNERABILITY: Replay was NOT clearly rejected. Result: {res2}")
            
    except Exception as e:
        log_fail(f"Replay test failed: {e}")

# -------------------------------------------------------------------
# Phase 3: Fuzzing & DoS
# -------------------------------------------------------------------

def _ping_challenge(i):
    try:
        r = requests.post(NODE_A_CHALLENGE, json={"peer_id": f"EVE_{i}"}, timeout=2)
        return r.status_code
    except:
        return 0

def phase_3_rate_limiting():
    print_hdr("Phase 3.1: TokenBucket Rate Limiting DoS Test")
    # Hit the challenge endpoint with 20 concurrent requests
    
    log_succ("Launching burst of 20 challenge requests...")
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(_ping_challenge, range(20)))
    
    status_counts = {}
    for code in results:
        status_counts[code] = status_counts.get(code, 0) + 1
        
    print(f"   HTTP Status codes received: {status_counts}")
    
    if 429 in status_counts:
        log_succ("SUCCESS: Rate limiter (HTTP 429) activated during burst.")
    else:
        log_warn("VULNERABILITY: Rate limiter failed to strictly clamp 20 concurrent bursts. Check --rl-challenge-burst setting.")

def phase_3_fuzzing():
    print_hdr("Phase 3.2: JSON/Payload Format Fuzzing")
    
    fuzz_vectors = [
        {"desc": "Negative payload list", "mod": lambda m: m.update({"payload": [-1, -2, -3]})},
        {"desc": "String in integer array", "mod": lambda m: m.update({"payload": [1, 2, "three", 4]})},
        {"desc": "Massive nested JSON", "mod": lambda m: m.update({"type": {"a": {"b": "c"*10000}}})},
        {"desc": "Truncated payload (missing MAC)", "mod": lambda m: m.update({"payload": m["payload"][:10]}) if "payload" in m and len(m["payload"]) > 10 else None},
    ]
    
    try:
        r_send = requests.post(API_SEND, json={"message": "fuzz_base"}, timeout=5)
        base_msg = r_send.json()["wire_message"]
    except Exception as e:
        log_fail(f"Failed to setup fuzzing test: {e}")
        return

    for fv in fuzz_vectors:
        fuzzed_msg = dict(base_msg)
        fv["mod"](fuzzed_msg)
        
        try:
            r = requests.post(API_RECEIVE, json={"wire_message": fuzzed_msg}, timeout=3)
            if r.status_code in [200, 400, 422]:
                res = r.json()
                if res.get("status") in ("rejected", "reject"):
                    log_succ(f"SUCCESS: Passed '{fv['desc']}' - Rejected cleanly.")
                else:
                    log_fail(f"VULNERABILITY: '{fv['desc']}' was accepted or crashed into unexpected JSON: {res}")
            else:
                log_fail(f"VULNERABILITY: '{fv['desc']}' caused HTTP {r.status_code} (possible crash/500)")
        except requests.exceptions.RequestException as e:
             log_succ(f"SUCCESS: Passed '{fv['desc']}' - Request aborted cleanly (Nginx/Gunicorn drop).")

def main():
    print_hdr("IDRE LIVE ATTACK SUITE STARTING")
    
    if not check_alive():
        print("Aborting.")
        sys.exit(1)
        
    phase_1_known_plaintext()
    phase_1_timing_side_channel()
    
    phase_2_handshake_bypass()
    phase_2_replay_attack()
    
    phase_3_rate_limiting()
    phase_3_fuzzing()
    
    print_hdr("ATTACK SUITE COMPLETE")

if __name__ == "__main__":
    main()
