#!/usr/bin/env python3
"""
Verify IDRE Protocol Message Streaming (Bidirectional).

This script bypasses the HTTP layer and directly instantiates FieldBoundNode
to verify that a stream of varying messages can be sent and received correctly
in both directions (A->B and B->A).
"""

import sys
import os
import time
import logging
import random
from typing import Dict, Any, List

# Ensure we can import from the repo root
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

try:
    # Try importing from the package if installed/available
    from scripts.hive_v12_node_server import FieldBoundNode, parse_int_tuple
except ImportError:
    # Fallback to direct file import if needed (though sys.path should handle it)
    # This might require a bit of hackery if hive_v12_node_server isn't a proper module
    # distinct from the script.
    # Let's assume the sys.path insertion works for `idre_clean` imports inside the server script,
    # but to import the server script *itself* as a module, we might need it to be importable.
    # The file is `scripts/hive_v12_node_server.py`.
    pass

# We need to import FieldBoundNode from the script. 
# Since it's in scripts/, and we are running from scripts/ (or root), let's fix imports.
import importlib.util
spec = importlib.util.spec_from_file_location("hive_v12_node_server", os.path.join(_REPO_ROOT, "scripts", "hive_v12_node_server.py"))
hive_server_mod = importlib.util.module_from_spec(spec)
sys.modules["hive_v12_node_server"] = hive_server_mod
spec.loader.exec_module(hive_server_mod)

FieldBoundNode = hive_server_mod.FieldBoundNode
parse_int_tuple = hive_server_mod.parse_int_tuple


class TestNode(FieldBoundNode):
    """
    Subclass of FieldBoundNode that captures received messages for verification.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.received_messages: List[str] = []

    def receive(self, msg: Dict[str, Any], prev_hop_id: str) -> Dict[str, Any]:
        result = super().receive(msg, prev_hop_id)
        
        # If delivery was successful, we want to capture the decrypted text.
        # But super().receive() does NOT return the text, only {"status": "delivered"}.
        # So we must decrypt it ourselves here if the status is "delivered".
        if result.get("status") == "delivered":
             # Extract needed fields for decryption
            session_id = str(msg.get("session_id", ""))
            nonce = int(msg.get("nonce", 0))
            # internal logic of receive() gets the session... we need to access it.
            sess = self.sessions.get(prev_hop_id)
            if sess:
                # We need to reconstruct AAD to decrypt.
                # The server code does:
                # header = { ... keys from msg ... }
                # aad = canonical_json(header)
                # But we can cheat: The server *already* decrypted it successfully.
                # For this test, let's just re-decrypt it. It's inefficient but fine for a test.
                
                # Reconstruct header for AAD exactly as the server does in receive()
                header = {
                    "type": str(msg.get("type", "")),
                    "field_profile_id": str(msg.get("field_profile_id", "")),
                    "session_id": str(msg.get("session_id", "")),
                    "nonce": int(msg.get("nonce", 0)),
                    "created_at_ms": int(msg.get("created_at_ms", 0)),
                    "expires_at_ms": int(msg.get("expires_at_ms", 0)),
                    "src_node_id": str(msg.get("src_node_id", "")),
                    "dst_node_id": str(msg.get("dst_node_id", "")),
                    "hop_count": int(msg.get("hop_count", 0)),
                    "max_hops": int(msg.get("max_hops", 0)),
                }
                aad = hive_server_mod.canonical_json(header)
                payload = msg.get("payload")
                
                # Decrypt
                ok, text = self.decrypt_message(
                    payload, 
                    session_id=sess.session_id, 
                    nonce=nonce, 
                    ephemeral_salt=sess.ephemeral_salt, 
                    aad=aad
                )
                if ok:
                    self.received_messages.append(text)
                    print(f"[{self.node_id}] CAPTURED: {text[:60]}...")
                else:
                    print(f"[{self.node_id}] FAILED TO RE-DECRYPT captured message")
                    
        return result


def setup_node(node_id: str, seed: int, port: int) -> TestNode:
    return TestNode(
        node_id=node_id,
        seed=seed,
        anchor_seeds=(7245,),
        anchor_weight=80.0,
        n_angles=72,
        scan_resolution=50,
        threshold=0.5,
        planes=4,
        tau_frac=0.55,
        print_deliveries=True,
        print_events=True,
        freeze_field=True,
        backend="frozen",
        content_codec="utf8",
        max_plaintext_bytes=65535,
    )


def perform_handshake(node_a: TestNode, node_b: TestNode):
    print(f"--- Handshake: {node_a.node_id} <-> {node_b.node_id} ---")
    
    # 1. A -> B Handshake
    # A asks B for a challenge
    print(f"[{node_a.node_id}] Requesting challenge from {node_b.node_id}...")
    chal_b = node_b.issue_challenge(peer_id=node_a.node_id)
    
    # A creates verify request
    print(f"[{node_a.node_id}] Creating verify req...")
    # Emulate client-side generation of session_id and ephemeral_salt
    rng = random.Random(node_a.seed) # deterministic for test
    session_id_ab = f"sess_{node_a.node_id}{node_b.node_id}_{random.randint(1000,9999)}"
    esalt_ab = random.getrandbits(31)
    
    msg_verify_a = node_a.create_verify_req(
        session_id=session_id_ab,
        ephemeral_salt=esalt_ab,
        challenge=chal_b.challenge
    )
    
    # B processes verify request
    print(f"[{node_b.node_id}] Processing verify req from {node_a.node_id}...")
    ok_b = node_b.process_verify_req(msg_verify_a, peer_id=node_a.node_id)
    assert ok_b, "B failed to verify A"
    print(f"[{node_b.node_id}] Verified A successfully.")


    # 2. B -> A Handshake (Mutual)
    print(f"[{node_b.node_id}] Requesting challenge from {node_a.node_id}...")
    chal_a = node_a.issue_challenge(peer_id=node_b.node_id)
    
    print(f"[{node_b.node_id}] Creating verify req...")
    # Reuse same session_id for simplicity or new one? 
    # The demo script uses the *same* session_id for both directions usually, but logically they are separate crypto contexts if not bound carefully.
    # The protocol supports reusing the session_id string.
    
    msg_verify_b = node_b.create_verify_req(
        session_id=session_id_ab,
        ephemeral_salt=esalt_ab,
        challenge=chal_a.challenge
    )
    
    print(f"[{node_a.node_id}] Processing verify req from {node_b.node_id}...")
    ok_a = node_a.process_verify_req(msg_verify_b, peer_id=node_b.node_id)
    assert ok_a, "A failed to verify B"
    print(f"[{node_a.node_id}] Verified B successfully.")
    
    print("--- Handshake Complete ---\n")


def test_streaming():
    # Setup
    node_a = setup_node("A", 7245, 8890)
    node_b = setup_node("B", 7245, 8891) # Same seed for field compatibility
    
    perform_handshake(node_a, node_b)
    
    test_messages = [
        "Hello World",
        "Test Message 2",
        "A longer message to test fragmentation or just larger payload handling in the stream context.",
        "Special characters: !@#$%^&*()_+{}|:<>?",
        "Unicode: 🐛🦋🐞 ok",
        "End of Stream"
    ]
    
    print(f"--- Starting Bidirectional Stream ({len(test_messages)} msgs each) ---")
    
    for i, msg in enumerate(test_messages):
        msg_a_to_b = f"[A->B seq={i}] {msg}"
        msg_b_to_a = f"[B->A seq={i}] {msg} (reply)"
        
        # A Sends to B
        print(f"Sending A->B: {msg_a_to_b}")
        wire_a = node_a.send(dst_node_id="B", content=msg_a_to_b)
        assert wire_a, "A failed to produce wire message"
        
        # B Receives
        res_b = node_b.receive(wire_a, prev_hop_id="A")
        assert res_b["status"] == "delivered", f"B failed to receive: {res_b}"
        
        # Verify B captured matches
        assert node_b.received_messages[-1] == msg_a_to_b, "B received content mismatch!"
        
        # B Sends to A
        print(f"Sending B->A: {msg_b_to_a}")
        wire_b = node_b.send(dst_node_id="A", content=msg_b_to_a)
        assert wire_b, "B failed to produce wire message"
        
        # A Receives
        res_a = node_a.receive(wire_b, prev_hop_id="B")
        assert res_a["status"] == "delivered", f"A failed to receive: {res_a}"
        
        # Verify A captured matches
        assert node_a.received_messages[-1] == msg_b_to_a, "A received content mismatch!"
        
        print(f"Sequence {i} OK.\n")
        
    print("--- Stream Verification PASSED ---")
    print(f"Total A->B: {len(node_b.received_messages)}")
    print(f"Total B->A: {len(node_a.received_messages)}")


if __name__ == "__main__":
    try:
        test_streaming()
        sys.exit(0)
    except AssertionError as e:
        print(f"TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"TEST ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(2)
