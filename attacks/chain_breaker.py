#!/usr/bin/env python3
"""
Chain Breaker: State Desynchronization via Inconsistent Rollback.

Demonstrates a vulnerability in the "Epoch Anchor" / Rolling Chain Hash mechanism.
If a sender (Node A) rolls back their chain hash (using `rollback_anchor`) due to 
a perceived delivery failure (e.g., timeout), but the receiver (Node B) actually 
received and processed the message, their states permanently diverge.

Future messages from A will be encrypted with the rolled-back hash, while B 
expects updates based on the previous (dropped) state.
"""

import sys
import os
import time
import argparse
import logging
from typing import Optional

# --- Path Injection ---
# 1. Add current dir (scripts run from root)
if os.getcwd() not in sys.path:
    sys.path.append(os.getcwd())

# 2. Add repo root relative to file
# attacks/chain_breaker.py -> .. -> idre_clean(root)
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.append(root_dir)

# 3. Add PARENT of repo root (to allow 'import idre_clean')
parent_dir = os.path.abspath(os.path.join(root_dir, ".."))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

try:
    from idre_clean.hive.node import FieldBoundNode
except ImportError:
    try:
        import idre_clean
        from idre_clean.hive.node import FieldBoundNode
    except ImportError:
        try:
             from hive.node import FieldBoundNode
        except ImportError:
             print("[!] FATAL: Could not import hive.node")
             sys.exit(1)

# Configure Logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("chain_breaker")

def setup_nodes():
    # Setup Node A and B with shared vocab/settings
    # Using frozen backend for deterministic behavior (logic applies to lattice too)
    # CRITICAL: They must share the seed to derive the same MAC keys in this implementation.
    SHARED_SEED = 9999
    
    a = FieldBoundNode(
        node_id="A", seed=SHARED_SEED, anchor_seeds=(SHARED_SEED,), anchor_weight=10.0,
        n_angles=72, scan_resolution=50, threshold=0.5, planes=4, tau_frac=0.55,
        print_deliveries=True, print_events=True, freeze_field=True, backend="frozen"
    )
    b = FieldBoundNode(
        node_id="B", seed=SHARED_SEED, anchor_seeds=(SHARED_SEED,), anchor_weight=10.0,
        n_angles=72, scan_resolution=50, threshold=0.5, planes=4, tau_frac=0.55,
        print_deliveries=True, print_events=True, freeze_field=True, backend="frozen"
    )
    return a, b

def exchange_verify_req(src: FieldBoundNode, dst: FieldBoundNode):
    # Simulated Handshake
    sid = "SESSION_123"
    esalt = 999
    
    # Src -> Dst
    chal_rec = dst.issue_challenge(src.node_id)
    # print(f"DEBUG: Issued challenge {chal_rec.challenge} for {src.node_id}")
    # print(f"DEBUG: VerifyReq creation with sid={sid} nonce=random")
    
    req = src.create_verify_req(sid, esalt, chal_rec.challenge)
    
    # We must ensure profile IDs match.
    # src.field_profile_id == dst.field_profile_id?
    if src.field_profile_id != dst.field_profile_id:
        print(f"DEBUG: Profile Mismatch! {src.field_profile_id} vs {dst.field_profile_id}")
    
    if not dst.process_verify_req(req, src.node_id):
        raise RuntimeError(f"Handshake failed: {src.node_id}->{dst.node_id}")
        
    return sid, esalt

def attack_pipeline():
    log.info("[*] Setting up Chain Breaker Test...")
    a, b = setup_nodes()
    
    # 1. Establish Session (A -> B)
    # Note: process_verify_req initializes the session on B.
    # A needs to initialize its session on A too?
    # `process_verify_req` creates session on Receiver.
    # Sender (A) must have session created via `create_verify_req`? No, create just makes a msg.
    # Sender needs `force_session` or similar to know B is ready?
    # In `node.py`, `send` checks `self.sessions`.
    # How does A adds B to its sessions?
    # Typically A receives a VerifyReq from B (Mutual Auth).
    # Or A just calls `force_session`?
    # Let's perform mutual handshake.
    
    log.info("[*] Performing Mutual Handshake...")
    sid_ab, salt = exchange_verify_req(a, b) # A -> B (B has session)
    sid_ba, _ = exchange_verify_req(b, a) # B -> A (A has session)
    
    # Important: In standard protocol, they might share the same Session ID?
    # Usually they do. Let's align their session IDs for clarity, though `node.py` treats them per-peer.
    # We just need A to have a session for B.
    
    # Check Sync
    log.info("[*] Verifying Initial Sync...")
    msg1 = a.send(b.node_id, "Hello B, I am A!")
    res1 = b.receive(msg1, a.node_id)
    if res1["status"] != "delivered":
        log.error(f"[!] Init Sync Failed: {res1}")
        return
    log.info(f"    [OK] Msg 1 Delivered. Chain hashes updated.")
    
    # Capture State
    hash_a_1 = a.sessions[b.node_id].chain_hash
    hash_b_1 = b.sessions[a.node_id].chain_hash
    log.info(f"    State A: {hash_a_1[:8].hex()} | State B: {hash_b_1[:8].hex()}")
    assert hash_a_1 == hash_b_1
    
    # 2. The Attack: "Inconsistent Rollback"
    # Scenario: A sends Msg 2. B receives it.
    # But A thinks it failed (e.g. network timeout / no ACK), so A rolls back.
    
    log.info("\n[*] Simulating 'Lost ACK' Scenario...")
    log.info("    Step 1: A sends Msg 2...")
    msg2 = a.send(b.node_id, "Msg 2: Critical Data")
    
    log.info("    Step 2: B receives Msg 2 (Processing...)")
    res2 = b.receive(msg2, a.node_id)
    if res2["status"] != "delivered":
        log.error("[!] B rejected Msg 2! Test Invalid.")
        return
    log.info("    [OK] B processed Msg 2. Chain advanced.")
    
    log.info("    Step 3: A times out and performs ROLLBACK...")
    a.rollback_anchor(b.node_id)
    log.info("    [!] A reverted chain hash.")
    
    # Compare States
    hash_a_current = a.sessions[b.node_id].chain_hash
    hash_b_current = b.sessions[a.node_id].chain_hash
    log.info(f"    State A (Rolled Back): {hash_a_current[:8].hex()}")
    log.info(f"    State B (Advanced):    {hash_b_current[:8].hex()}")
    
    if hash_a_current == hash_b_current:
        log.error("[FAIL] States are still equal? Rollback failed to diverge?")
        return
        
    log.info("[*] Divergence Confirmed.")
    
    # 3. Verify Permanent Desync
    log.info("\n[*] Testing Desynchronization (Msg 3)...")
    log.info("    A sends Msg 3 (Retrying Msg 2 or sending new data)...")
    
    # A encrypts with OLD hash (H1). B expects NEW hash (H2).
    msg3 = a.send(b.node_id, "Msg 3: Can you hear me?")
    
    res3 = b.receive(msg3, a.node_id)
    log.info(f"    B Response: {res3}")
    
    if res3["status"] == "reject":
        log.info("[SUCCESS] Chains broken! B rejected Msg 3.")
        log.info("          Reason: " + res3.get("reason", "unknown"))
    else:
        log.error("[FAIL] B accepted Msg 3? Desync failed.")

if __name__ == "__main__":
    attack_pipeline()
