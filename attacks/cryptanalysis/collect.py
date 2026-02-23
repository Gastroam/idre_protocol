import os
import json
import time
import requests

BASE_URL = 'https://idre.mti-evo.online'

def establish_session():
    requests.post(f"{BASE_URL}/api/demo/handshake", timeout=10)

def send_message(msg):
    r = requests.post(f"{BASE_URL}/api/demo/send", json={"message": msg}, timeout=10)
    return r.json()

def collect_dataset(count, msg_gen, label):
    os.makedirs(os.path.dirname(__file__), exist_ok=True)
    out_file = os.path.join(os.path.dirname(__file__), f"data_{label}.json")
    print(f"Collecting {count} samples for {label}...")
    
    establish_session()
    
    data = []
    for i in range(count):
        msg = msg_gen(i)
        try:
            res = send_message(msg)
            wire_msg = res.get("wire_message")
            if wire_msg:
                # Extract ct_ints right here to save space
                payload = wire_msg["payload"]
                n = payload[0]
                ct_ints = payload[1 : 1 + n]
                data.append({
                    "seq": i,
                    "ct_ints": ct_ints
                })
        except Exception as e:
            print(f"Error on {i}: {e}")
            time.sleep(1) # Backoff
            
        if (i+1) % 50 == 0:
            print(f"  ... {i+1} / {count}")
    
    with open(out_file, "w") as f:
        json.dump(data, f)
    print(f"Saved {len(data)} to {out_file}")

if __name__ == "__main__":
    # We send exactly 64 bytes of constant 'A' (0x41). 
    # Because of IDRE framing:
    # 4 bytes Len + 2 bytes PackLen + 4 bytes PackCRC = 10 bytes overhead.
    # Block 0 (32 bytes) = 10 bytes overhead + 22 bytes 'A'.
    # Block 1 (32 bytes) = 32 bytes 'A' (fully controlled!).
    # Block 2 (32 bytes) = 10 bytes 'A' + 22 bytes 0x00 padding.
    # So Block 1 and 2 are fully uniform and invariant under permutation!
    msg_A = "A" * 64
    collect_dataset(500, lambda i: msg_A, "uniform_A_64")
    
    # Counter 0..31
    # We want block 1 to be the counter. So we pad first 22 bytes with 'A', then 32 bytes counter.
    # 22 bytes + 32 bytes = 54 bytes.
    # Using ascii chars 0..31 ensures 1-byte utf-8 encoding.
    msg_counter = "A" * 22 + "".join(chr(x) for x in range(32))
    collect_dataset(500, lambda i: msg_counter, "counter_block1")

    # Pseudo-random chars 0..127 to get random ciphertext baseline
    import random
    def random_msg(i):
        return "".join(chr(random.randint(0, 127)) for _ in range(64))
    collect_dataset(500, random_msg, "random_64")
