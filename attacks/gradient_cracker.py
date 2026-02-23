#!/usr/bin/env python3
"""
Gradient Descent "Seed" Cracker (Weight Recovery).

Demonstrates that public projection planes allowing "Field-Bound Identity"
also allow an attacker to recover the secret Weight Vector `w` if they 
capture enough "Fingerprint Bits".

The attack Formulates specific linear/non-linear constraints:
    Bit_i = 1  =>  | P_i . w | > tau
    Bit_i = 0  =>  | P_i . w | <= tau

We solve for `w` using optimization (Gradient Descent) rather than brute force.
Once `w` is recovered, the attacker can Clone the identity.
"""

import sys
import os
import time
import numpy as np
import argparse
from typing import List, Tuple

# --- Path Injection ---
# 1. Add current dir (scripts run from root)
if os.getcwd() not in sys.path:
    sys.path.append(os.getcwd())

try:
    # Try fully qualified first (standard)
    from core.physics_v12 import derive_locked_planes, scan_fingerprint_bits
    from hive.node import FieldBoundNode
    from core.vocab_codec import Vocab
except ImportError:
    try:
        # Fallback for script-style execution from repo root
        from core.physics_v12 import derive_locked_planes, scan_fingerprint_bits
        from hive.node import FieldBoundNode
        from core.vocab_codec import Vocab
    except ImportError as e:
        print(f"[!] Import Error: {e}")
        print(f"    sys.path: {sys.path}")
        print("[!] FATAL: Could not import core modules.")
        sys.exit(1)

def sigmoid(x):
    return 1 / (1 + np.exp(-x))

class GradientCracker:
    def __init__(self, embedding_dim=64, planes=4, n_angles=72):
        self.dims = embedding_dim
        self.n_planes = planes
        self.n_angles = n_angles
        self.plane_list = []

    def load_planes(self):
        self.plane_list = derive_locked_planes(self.dims, self.n_planes)
        print(f"[*] Loaded {len(self.plane_list)} Public Projection Planes")

    def get_fingerprint(self, w: np.ndarray) -> List[int]:
        # Helper to call scan_fingerprint_bits matches the victim's logic
        out = []
        for i, (u_p, w_p) in enumerate(self.plane_list):    
            
            ww = w.reshape(-1)
            a = float(np.dot(u_p, ww))
            b = float(np.dot(w_p, ww))
            amp = float(np.hypot(a, b))
            tau = max(amp * 0.55, 1e-9)
            
            bits = scan_fingerprint_bits(
                weights=ww,
                bias=0.0,
                tau=tau,
                u=u_p,
                w=w_p,
                n_angles=self.n_angles,
                scan_resolution=50,
                threshold=0.5
            )
            out.extend(bits)
        return out

    def solve(self, target_bits: List[int], max_steps=10000) -> Tuple[np.ndarray, float]:
        """
        Recover w using Evolution Strategy (1+1).
        We use the actual scan function as the oracle.
        """
        print(f"[*] Starting Evolution Strategy Attack on {len(target_bits)} bits...")
        
        # 1. Random Init
        w = np.random.randn(self.dims)
        w /= np.linalg.norm(w)
        
        current_bits = self.get_fingerprint(w)
        current_acc = np.mean(np.array(current_bits) == np.array(target_bits))
        
        sigma = 0.1 # Mutation strength
        
        for step in range(max_steps):
            # Mutate
            noise = np.random.randn(self.dims) * sigma
            candidate = w + noise
            candidate /= np.linalg.norm(candidate)
            
            # Eval
            cand_bits = self.get_fingerprint(candidate)
            cand_acc = np.mean(np.array(cand_bits) == np.array(target_bits))
            
            if cand_acc >= current_acc:
                w = candidate
                current_acc = cand_acc
                # Adaptive sigma: if success, slight increase? Or just keep constant?
                # 1/5th rule: success rate should be 0.2.
                # If we accepted, maybe sigma is good.
                
                if cand_acc == 1.0:
                    print(f"    [Step {step}] CRACKED! Accuracy: 100%")
                    return w, 1.0
            
            # Simple annealing / adaptation
            if step % 200 == 0:
                 print(f"    [Step {step}] Acc: {current_acc:.2f} (Sigma: {sigma:.3f})")
                 # If stuck, reduce sigma?
                 # Actually, usually getting closer requires smaller steps.
                 sigma *= 0.99 
                 if sigma < 0.001: sigma = 0.1 # Reset if too small (simulated annealing restart)
        
        return w, current_acc

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=7245, help="Target Seed (Simulated Victim)")
    parser.add_argument("--steps", type=int, default=2000)
    parser.add_argument("--pepper", type=str, default="", help="Secret Pepper (Defense in Depth)")
    args = parser.parse_args()

    # 1. Simulate Victim (Generate Target Fingerprint)
    print(f"[*] Simulating Victim Node (Seed={args.seed})...")
    if args.pepper:
        print(f"    [!] Pepper Enabled: '{args.pepper}'")
    
    # We create a temporary node to generate true bits
    # We match the config: planes=4, n_angles=72, backend=lattice?
    
    tokens = ["<pad>", "<a>", "<b>", "<c>"]
    t2i = {t: i for i, t in enumerate(tokens)}
    dummy_vocab = Vocab(tokens=tokens, token_to_index=t2i, vocab_id=b"DUMMY", lens_by_first_char={})

    victim = FieldBoundNode(node_id="VICTIM", seed=args.seed, anchor_seeds=(args.seed,), anchor_weight=80.0,
        n_angles=72, scan_resolution=50, threshold=0.5, planes=4, tau_frac=0.55,
        print_deliveries=False, print_events=False, freeze_field=True, backend="frozen",
        pepper=args.pepper,
        vocab=dummy_vocab
    )
    target_bits = victim.fingerprint_bits(args.seed)
    print(f"    Captured {len(target_bits)} bits.")
    
    # 2. Attack
    cracker = GradientCracker(embedding_dim=64, planes=4, n_angles=72)
    cracker.load_planes()
    
    start_t = time.time()
    recovered_w, acc = cracker.solve(target_bits, max_steps=args.steps)
    end_t = time.time()
    
    print(f"\n[*] Attack Finished in {end_t - start_t:.2f}s")
    print(f"    Final Accuracy: {acc*100:.1f}%")
    
    if acc > 0.95:
        print("[SUCCESS] WEIGHTS RECOVERED!")
        print("          Attacker can now clone the identity.")
        
        # Verify Clone
        # Can we create a node with these RAW WEIGHTS?
        # The current `FieldBoundNode` takes a SEED.
        # But `FrozenSubstrate` takes `seed_scales`...
        # We can't easily inject raw weights into the Python Class without modding it.
        # But mathematically, we have the key.
    else:
        print("[FAIL] Could not converge on weights.")

if __name__ == "__main__":
    main()
