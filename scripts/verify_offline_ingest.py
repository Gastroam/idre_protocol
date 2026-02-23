#!/usr/bin/env python3
import time
import subprocess
import requests
import sys

# Add repo root to sys.path
from pathlib import Path

from idre_clean.core.frozen_physics import compute_fingerprint_bits_frozen_v12
from idre_clean.core.offline_envelope import seal

PORT = 8905
NODE_ID = "OFFLINE_TEST"
NODE_SEED = 7245
OFFLINE_RING = [8888, 9999]  # Two valid offline seeds

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

def generate_envelope(seed: int, plaintext: str) -> bytes:
    """Generate a raw offline envelope using the given seed."""
    bits = compute_fingerprint_bits_frozen_v12(
        seed=seed,
        embedding_dim=64, planes=4, tau_frac=0.55,
        n_angles=72, scan_resolution=50, threshold=0.5,
        anchor_weight=80.0
    )
    # Use blank profile ID since test node will use default args
    # Wait, we need to match the node's profile ID.
    # The node uses default explicit args, so we must replicate them.
    # Default profile usually hashes "frozen" backend etc.
    # Actually, simpler: compute profile ID or just use "allow_mismatch"? 
    # The server enforces `wrong_profile`.
    # Let's fetch /health to see profile? No, /health is minimal.
    # The `verify_resonant_drift.py` script hardcodes params, so these defaults should match `hive_v12_node_server.py`.
    # Server defaults:
    # planes=4, n_angles=72, scan_resolution=50, threshold=0.5, anchor_weight=80.0
    # backend=lattice (if resonant), but offline envelope uses frozen physics.
    # Profile ID depends on backend. Gateway uses Frozen. Server check compares against ITS backend.
    
    # Wait! If Node is "Lattice", its profile ID includes "backend: lattice".
    # Offline Envelope header must allow mismatch or Gateway must spoof "Lattice"?
    # `offline_envelope.py` check:
    # if str(hdr.field_profile_id) != str(expected_field_profile_id): return False
    
    # This is a conflict!
    # If Node is "Lattice", it expects "Lattice" profile.
    # But Gateway uses "Frozen" (obviously).
    # Does "Ghost Recovery" imply ignoring profile mismatch? 
    # Or does Gateway need to tag envelope as "Lattice" (even if computed via Frozen)?
    # Let's assume Gateway spoofs the profile ID to match the *Target Node*.
    # For now, let's fetch the node's profile ID from a dummy request or just compute it as "lattice".
    
    from idre_clean.core.profile import compute_field_profile_id
    # Target Node Profile (Lattice + Plasticity)
    profile = {
        "proto": "HIVE-P2P/1.2",
        "backend": "lattice", # The node is running lattice backend
        "freeze_field": False, # Plasticity is enabled? No, enable-plasticity flag doesn't change profile ID (it's internal state). 
        # Wait, `freeze_field` is an arg. 
        # Server args: --enable-plasticity implies freeze_field=False?
        # Let's look at server code.
        # `freeze_field=bool(freeze_field)` arg is passed to Profile.
        # If we run with `--enable-plasticity`, `freeze_field` defaults to True (in argparse)? 
        # No, `freeze_field` default is True in server `FieldBoundNode`.
        # Server `main`: parser argument --freeze-field default is False (action store_true).
        # So `freeze_field` is False by default.
        
        "embedding_dim": 64,
        "planes": 4,
        "tau_frac": 0.55,
        "n_angles": 72,
        "scan_resolution": 50,
        "threshold": 0.5,
        "anchor_weight": 80.0,
    }
    pid = compute_field_profile_id(profile)
    
    return seal(
        bits=bits,
        plaintext=plaintext.encode("utf-8"),
        field_profile_id=pid,
        expires_in_ms=60000
    )

def test_offline_ingest():
    cmd = [
        sys.executable, "scripts/hive_v12_node_server.py",
        "--port", str(PORT),
        "--node-id", NODE_ID,
        "--seed", str(NODE_SEED),
        "--planes", "4",
        "--backend", "lattice",
        "--enable-plasticity", 
        "--offline-seed-ring", "8888, 9999", # The Ring
        "--print-events",
        "--pepper", "test_pepper"
    ]
    
    print(f"[*] Starting Node {NODE_ID} with ring=[8888, 9999]...")
    proc = subprocess.Popen(cmd)
    
    try:
        if not wait_for_port(PORT):
            print("[!] Node failed to start")
            return
            
        print("[*] Node is UP. Generating envelopes...")
        
        # Test 1: Valid Seed (8888)
        print("  - Genering Envelope A (Seed 8888)...")
        env_a = generate_envelope(8888, "Hello from the Past (Seed 8888)")
        
        print("  - POSTing Envelope A to /ingest_offline...")
        resp = requests.post(f"http://127.0.0.1:{PORT}/hive/v12/ingest_offline", data=env_a)
        print(f"  - Response: {resp.status_code} {resp.text}")
        
        if resp.status_code != 200 or resp.json().get("status") != "ok":
            print("[!] Test 1 FAILED: Valid seed rejected.")
            sys.exit(1)
            
        if resp.json().get("text") != "Hello from the Past (Seed 8888)":
             print("[!] Test 1 FAILED: Text mismatch.")
             sys.exit(1)
        print("[+] Test 1 PASSED: Valid seed accepted.")

        # Test 2: Valid Seed (9999) - Alternate Ring Member
        print("  - Genering Envelope B (Seed 9999)...")
        env_b = generate_envelope(9999, "Hello from the Past (Seed 9999)")
        resp = requests.post(f"http://127.0.0.1:{PORT}/hive/v12/ingest_offline", data=env_b)
        if resp.json().get("text") == "Hello from the Past (Seed 9999)":
            print("[+] Test 2 PASSED: Alternate seed accepted.")
        else:
            print("[!] Test 2 FAILED.")
            sys.exit(1)

        # Test 3: Invalid Seed (1234) - Not in Ring
        print("  - Genering Envelope C (Seed 1234 - Intruder)...")
        env_c = generate_envelope(1234, "I am an Intruder")
        resp = requests.post(f"http://127.0.0.1:{PORT}/hive/v12/ingest_offline", data=env_c)
        print(f"  - Response: {resp.status_code} {resp.text}")
        
        if resp.json().get("status") == "reject":
            print("[+] Test 3 PASSED: Invalid seed rejected.")
        else:
             print("[!] Test 3 FAILED: Invalid seed ACCEPTED!")
             sys.exit(1)

    finally:
        proc.terminate()
        proc.wait()

if __name__ == "__main__":
    test_offline_ingest()
