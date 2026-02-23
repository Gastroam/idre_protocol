import os
import json
import math
import pandas as pd
import numpy as np
from scipy.stats import chisquare
import matplotlib.pyplot as plt

def load_data(filename):
    with open(os.path.join(os.path.dirname(__file__), filename), "r") as f:
        return json.load(f)

def run_stats_on_bytes(byte_list, label):
    if not byte_list:
        print(f"No bytes found for {label}")
        return

    freq = np.bincount(byte_list, minlength=256)
    expected = len(byte_list) / 256.0
    chi_sq, p_value = chisquare(freq, f_exp=[expected]*256)
    
    bits = np.unpackbits(np.array(byte_list, dtype=np.uint8))
    ones = int(np.sum(bits))
    zeros = len(bits) - ones
    s_obs = abs(ones - zeros) / math.sqrt(len(bits))
    p_value_monobit = math.erfc(s_obs / math.sqrt(2))
    
    s = pd.Series(bits)
    ac_1 = s.autocorr(lag=1)
    ac_8 = s.autocorr(lag=8)
    
    v_obs = 1
    for i in range(1, len(bits)):
        if bits[i] != bits[i-1]:
            v_obs += 1
            
    pi_p = ones / len(bits)
    if pi_p == 0 or pi_p == 1.0 or len(bits) == 0:
        p_value_runs = 0.0
    elif abs(pi_p - 0.5) >= (2 / math.sqrt(len(bits))):
        p_value_runs = 0.0
    else:
        num = abs(v_obs - 2*len(bits)*pi_p*(1-pi_p))
        den = 2 * math.sqrt(2*len(bits)) * pi_p * (1-pi_p)
        p_value_runs = math.erfc(num / den)
        
    print(f"\n--- {label} ---")
    print(f"Total Bytes: {len(byte_list)}")
    print(f"Chi-Sq Distr p-value: {p_value:.5f} (>0.01 = Uniform)")
    print(f"NIST Monobit p-value: {p_value_monobit:.5f} (>0.01 = Random)")
    print(f"NIST Runs p-value:    {p_value_runs:.5f} (>0.01 = Random)")
    print(f"Autocorr (Lag 1 bit): {ac_1:.5f} (near 0 = No pattern)")
    print(f"Autocorr (Lag 8 bit): {ac_8:.5f} (near 0 = No pattern)")

    plt.figure()
    plt.bar(range(256), freq, color='blue', alpha=0.7)
    plt.title(f'Byte Distribution Histogram - {label}')
    plt.xlabel('Byte Value')
    plt.ylabel('Frequency')
    plt.axhline(expected, color='red', linestyle='dashed', linewidth=1)
    plot_file = os.path.join(os.path.dirname(__file__), f"hist_{label}.png")
    plt.savefig(plot_file)
    print(f"Saved histogram to {plot_file}")
    plt.close()

if __name__ == "__main__":
    if os.path.exists(os.path.join(os.path.dirname(__file__), "recovered_keystreams.json")):
        keystreams = load_data("recovered_keystreams.json")
        all_k_bytes = []
        for ks in keystreams:
            all_k_bytes.extend(ks["k_block1"])
        run_stats_on_bytes(all_k_bytes, "Recovered_Keystream_K1")
        
    if os.path.exists(os.path.join(os.path.dirname(__file__), "data_random_64.json")):
        ct_data = load_data("data_random_64.json")
        all_ct_bytes = []
        for msg in ct_data:
            all_ct_bytes.extend(msg["ct_ints"])
        run_stats_on_bytes(all_ct_bytes, "Raw_Ciphertext_RandomPT")

    if os.path.exists(os.path.join(os.path.dirname(__file__), "data_counter_block1.json")):
        ct_data = load_data("data_counter_block1.json")
        all_ct_bytes = []
        for msg in ct_data:
            if len(msg["ct_ints"]) >= 64:
                all_ct_bytes.extend(msg["ct_ints"][32:64])
        run_stats_on_bytes(all_ct_bytes, "Ciphertext_Block1_CounterPT")
