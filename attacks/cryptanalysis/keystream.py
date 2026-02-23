import os
import json

def load_data(filename):
    with open(os.path.join(os.path.dirname(__file__), filename), "r") as f:
        return json.load(f)

def recover_keystreams():
    data = load_data("data_uniform_A_64.json")
    
    keystreams = []
    
    # We used "A"*64.
    # Block 1 (bytes 32..63) is exactly 32 bytes of 0x41.
    for entry in data:
        seq = entry["seq"]
        ct_ints = entry["ct_ints"]
        
        # Ensure it's padded to at least 64 bytes
        if len(ct_ints) < 64:
            continue
            
        block1_ct = ct_ints[32:64]
        
        # K = C XOR P = C XOR 0x41
        k_t = [c ^ 0x41 for c in block1_ct]
        keystreams.append({
            "seq": seq,
            "k_block1": k_t
        })
        
    out_file = os.path.join(os.path.dirname(__file__), "recovered_keystreams.json")
    with open(out_file, "w") as f:
        json.dump(keystreams, f)
        
    print(f"Recovered {len(keystreams)} keystreams for block 1.")
    return keystreams

if __name__ == "__main__":
    recover_keystreams()
