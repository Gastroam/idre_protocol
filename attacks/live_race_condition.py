#!/usr/bin/env python3
import sys
import threading
import concurrent.futures
import requests
from pathlib import Path

_REPO_PARENT = str(Path(__file__).resolve().parents[1])
if _REPO_PARENT not in sys.path:
    sys.path.insert(0, _REPO_PARENT)

TARGET_URL = "http://idre.mti-evo.online"  # Live Node URL

def run_live_race_test(target_url):
    print(f"[*] Targeting live node at: {target_url}")
    
    print("[*] Requesting Challenge...")
    try:
        resp = requests.post(f"{target_url}/node-a/hive/v12/challenge", json={"peer_id": "RACE_ATTACKER"})
        print(f"    [!] Status Code: {resp.status_code}")
        print(f"    [!] Response Body: {resp.text[:100]}")
        resp_chal = resp.json()
        chal = resp_chal.get("challenge")
        if not chal:
            print("[!] Failed to get challenge:", resp_chal)
            return
    except Exception as e:
        print(f"[!] Could not connect to {target_url}: {e}")
        return

    print(f"    [+] Got challenge: {chal}")
    
    # We need to create a valid VerifyReq message locally
    # We can do this using FieldBoundNode locally, assuming we know the pepper and seed.
    # However, if it's purely a race condition test, we can just send the SAME message concurrently.
    # To create the message, we can instantiate a temporary local node just to sign it.
    from idre_clean.hive.node import FieldBoundNode
    try:
        from idre_clean.core.vocab_codec import Vocab
    except ImportError:
        from core.vocab_codec import Vocab

    tokens = ["<pad>", "<a>", "<b>", "<c>"]
    t2i = {t: i for i, t in enumerate(tokens)}
    dummy_vocab = Vocab(tokens=tokens, token_to_index=t2i, vocab_id=b"DUMMY", lens_by_first_char={})

    
    # Re-use the HiveClient to make it easier to create the request
    try:
        from idre_clean.hive.client import HiveClient
        client = HiveClient("http://127.0.0.1:9999") # Dummy URL, we just use it for create_verify_req
    except:
        pass

    print("[*] Generating VerifyReq locally...")
    node = FieldBoundNode(
        pepper="live_pepper_or_test_pepper", # Doesn't matter too much if the live node uses a different one, as long as it processes it and fails/succeeds
        node_id="RACE_ATTACKER",
        seed=12345,
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
        content_codec="utf8",
        max_plaintext_bytes=65535,
        vocab=dummy_vocab,
    )
    
    # Create the VERIFY_REQ payload
    req = node.create_verify_req(
        session_id="RACE_SESS_LIVE_1",
        ephemeral_salt=99999,
        challenge=chal
    )
    msg = req["msg"]

    print("[*] Submitting identical VerifyReq 20 times concurrently...")
    
    successes = 0
    failures = 0
    
    def submit_verify():
        try:
            r = requests.post(f"{target_url}/node-a/hive/v12/verify_req/process", json={
                "peer_id": "RACE_ATTACKER",
                "msg": msg,
                "ttl_s": 300
            }, timeout=10)
            return r.status_code, r.json()
        except Exception as e:
            return 500, {"error": str(e)}

    num_threads = 20
    barrier = threading.Barrier(num_threads)
    
    def align_and_submit():
        barrier.wait()
        return submit_verify()

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(align_and_submit) for _ in range(num_threads)]
        for f in concurrent.futures.as_completed(futures):
            status, json_resp = f.result()
            if status == 200 and json_resp.get("verified") is True:
                successes += 1
            else:
                failures += 1

    print(f"\n[*] Results: Successes (Accepted) = {successes}, Failures (Rejected) = {failures}")
    if successes == 1 and failures == num_threads - 1:
        print("[SUCCESS] Race condition mitigated! Exactly ONE request was accepted.")
    elif successes > 1:
        print("[FAIL] Race condition detected! Multiple identical VERIFY_REQ accepted.")
    elif successes == 0:
        print("[?] All requests were rejected. Did pepper mismatch or rate-limiting kick in?")

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else TARGET_URL
    run_live_race_test(url)
