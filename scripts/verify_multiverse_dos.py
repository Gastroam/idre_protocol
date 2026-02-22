
import time
import sys
import secrets
from pathlib import Path

# Add repo root to sys.path
# Add repo root and PARENT of repo root to sys.path
_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
_PARENT_ROOT = str(Path(__file__).resolve().parent.parent.parent)

if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
if _PARENT_ROOT not in sys.path:
    sys.path.insert(0, _PARENT_ROOT)

from idre_clean.hive.node import FieldBoundNode
from idre_clean.core.vocab_codec import Vocab

def make_dummy_vocab():
    return Vocab(["a"], {"a": 0}, b"dum", {})

def run_test():
    print("[*] Setting up Multiverse DoS & Plasticity Test...")
    
    # 1. Setup Nodes with Plasticity ENABLED
    # If plasticity is True, the lattice evolves on every encrypt.
    vocab = make_dummy_vocab()
    
    node_a = FieldBoundNode(
        node_id="A", seed=1000, anchor_seeds=(1000,), anchor_weight=10.0,
        n_angles=10, scan_resolution=10, threshold=0.1, planes=2, tau_frac=0.1,
        print_deliveries=False, print_events=False, freeze_field=True, backend="frozen", # Backend frozen implies no plasticity? 
        # Wait, if backend=frozen, plasticity is ignored in _evolve_lattice.
        # We need backend="lattice" to test true plasticity drift.
        # But lattice is heavy. Let's stick to "frozen" first for pure CPU bench of the FORK logic.
        # Then we can discuss Plasticity.
        vocab=vocab,
        healing_mode="multiverse"
    )
    
    node_b = FieldBoundNode(
        node_id="B", seed=1000, anchor_seeds=(1000,), anchor_weight=10.0,
        n_angles=10, scan_resolution=10, threshold=0.1, planes=2, tau_frac=0.1,
        print_deliveries=False, print_events=False, freeze_field=True, backend="frozen",
        vocab=vocab,
        healing_mode="multiverse"
    )

    # 2. Establish Session
    # Manually force session to skip handshake overhead
    sid = secrets.token_hex(16)
    esalt = secrets.randbits(32)
    
    # Force session A->B
    # We need A to send to B.
    # A needs a session object in timelines['B']
    # B needs a session object in timelines['A']
    
    # HACK: We use private methods or just standard flow?
    # Let's use `force_session` if available or just hand-craft.
    # node.py has `force_session`!
    node_a.force_session("B", sid, esalt)
    node_b.force_session("A", sid, esalt)
    
    print("[*] Session Forced.")

    # 3. Simulate Packet Loss (Create Gap)
    # A sends Packet 1 (Seq 1)
    msg1 = node_a.send("B", "packet_1")
    # B receives Packet 1 -> OK
    node_b.receive(msg1, "A")
    print("[*] Packet 1 Delivered.")
    
    # A sends Packet 2 (Seq 2) -> DRAGGED INTO VOID (Lost)
    msg2 = node_a.send("B", "packet_2_lost")
    print("[*] Packet 2 Lost (Simulated).")
    
    # A sends Packet 3 (Seq 3)
    msg3 = node_a.send("B", "packet_3")
    
    # 4. Measure Processing Time of Packet 3 (The Healing)
    print("[*] B receiving Packet 3 (Triggering Multiverse Fork)...")
    start = time.perf_counter()
    res = node_b.receive(msg3, "A")
    dur = (time.perf_counter() - start) * 1000.0
    
    print(f"    Result: {res['status']}")
    print(f"    Time: {dur:.4f} ms")
    
    if res['status'] != 'delivered':
        print("[!] HEALING FAILED!")
        # sys.exit(1)
    else:
        print("[+] HEALING SUCCESS!")
        # Check fork count
        forks = len(node_b.timelines.get("A", []))
        print(f"    Active Forks: {forks} (Expect 1 after collapse, or 2 if loosely kept?)")
        # Implementation says "Collapse! Winner=..." so it should be 1.
        
    # 5. DoS Benchmark
    # Now flood B with garbage packets while it thinks it has a fork?
    # Wait, if it collapsed, it has 1 fork.
    # We need to force it to KEEP 2 forks.
    # How? By sending a packet that FAILS both, so it forks?
    # Or by manually injecting a second session.
    
    print("\n[*] Starting Compute DoS Test (K=2 vs K=1)...")
    # Force 2 sessions for A
    sess1 = node_b.timelines["A"][0]
    sess2 = sess1.clone()
    sess2.session_id = "fork_2"
    node_b.timelines["A"].append(sess2)
    print(f"    Forks active: {len(node_b.timelines['A'])}")
    
    # Flood 1000 invalid packets
    garbage = {
        "type": "DATA", 
        "session_id": sid, 
        "nonce": 123, 
        "field_profile_id": node_b.field_profile_id,
        "src_node_id": "A", "dst_node_id": "B",
        "created_at_ms": int(time.time()*1000),
        "expires_at_ms": int(time.time()*1000) + 10000,
        "payload": [0]*100 # invalid payload
    }
    
    start = time.perf_counter()
    for _ in range(1000):
        node_b.receive(garbage, "A")
    dur_k2 = time.perf_counter() - start
    
    print(f"    K=2 Flood Time: {dur_k2:.4f}s")
    
    # Reset to K=1
    node_b.timelines["A"] = [sess1]
    start = time.perf_counter()
    for _ in range(1000):
        node_b.receive(garbage, "A")
    dur_k1 = time.perf_counter() - start
    
    print(f"    K=1 Flood Time: {dur_k1:.4f}s")
    print(f"    DoS Factor: {dur_k2 / dur_k1:.2f}x (Expected ~2.0x)")

if __name__ == "__main__":
    run_test()
