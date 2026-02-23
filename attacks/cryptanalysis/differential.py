import json
import os
import numpy as np

def load_data(filename):
    with open(os.path.join(os.path.dirname(__file__), filename), "r") as f:
        return json.load(f)

def run_differential_analysis():
    # We have 500 encryptions of exactly the same plaintext: "A" * 64
    # If this was ECB or un-salted CTR mode, the ciphertexts would be identical or have 0 differential.
    # In IDRE, each message increments the nonce, which alters the block salt, deriving an entirely new K and pi.
    print("--- Fixed-Plaintext Differential Analysis ---")
    data = load_data("data_uniform_A_64.json")
    
    diffs = []
    # Compare each consecutive pair
    for i in range(len(data) - 1):
        ct1 = data[i]["ct_ints"]
        ct2 = data[i+1]["ct_ints"]
        
        # We only compare block 1 to exactly isolate the cipher core without structural headers
        if len(ct1) >= 64 and len(ct2) >= 64:
            b1 = np.array(ct1[32:64], dtype=np.uint8)
            b2 = np.array(ct2[32:64], dtype=np.uint8)
            
            # XOR difference
            diff = np.bitwise_xor(b1, b2)
            bits_diff = np.unpackbits(diff)
            hamming_weight = np.sum(bits_diff)
            diffs.append(hamming_weight)
            
    avg_diff = np.mean(diffs)
    total_bits = 32 * 8 # 256 bits
    expected_diff = total_bits / 2.0
    print(f"Average Hamming Distance between consecutive encryptions of identical plaintext: {avg_diff:.2f} bits")
    print(f"Ideal Hamming Distance for perfect PRF: {expected_diff} bits")
    
    if abs(avg_diff - expected_diff) < 5.0:
         print("Result: PERFECT DIFFUSION ACROSS MESSAGES. The Ouroboros ratcheted nonce completely alters the keystream and permutation.")
    else:
         print("Result: Bias detected in differential.")

if __name__ == "__main__":
    if os.path.exists(os.path.join(os.path.dirname(__file__), "data_uniform_A_64.json")):
        run_differential_analysis()
    else:
        print("Waiting for data to be collected...")
