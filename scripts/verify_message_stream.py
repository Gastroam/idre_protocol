#!/usr/bin/env python3
"""
Verify IDRE Protocol Message Streaming (Bidirectional).

This script bypasses the HTTP layer and directly instantiates FieldBoundNode
to verify that a stream of varying messages can be sent and received correctly
in both directions (A->B and B->A).
"""

import sys
import os
import random
from typing import List

# Avoid Windows cp1252 console crashes if any Unicode slips into logs.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")

# Ensure we can import from the repo root
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

# Also add parent directory to path to allow 'import idre_clean' to work
_PARENT_DIR = os.path.dirname(_REPO_ROOT)
if _PARENT_DIR not in sys.path:
    sys.path.insert(0, _PARENT_DIR)

try:
    from idre_clean.hive.node import FieldBoundNode
except ImportError:
    # If package is not installed, we rely on sys.path insert above
    from hive.node import FieldBoundNode


class TestNode(FieldBoundNode):
    """
    Subclass of FieldBoundNode that captures received messages for verification.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.received_messages: List[str] = []

    # Intercept decryption to capture messages
    # Note: We must override decrypt_bytes because regular DATA packets use it directly 
    # (for Sliding Window trials), bypassing decrypt_message.
    def decrypt_bytes(self, payload, *, session_id, nonce, ephemeral_salt, aad=b"", codec=None, ratchet_key=None):
        # Call original decryption: returns (blob, reason, acks, tag)
        blob, reason, acks, tag = super().decrypt_bytes(
            payload, 
            session_id=session_id, 
            nonce=nonce, 
            ephemeral_salt=ephemeral_salt, 
            aad=aad,
            codec=codec,
            ratchet_key=ratchet_key
        )
        
        # If successful, capture the content
        if blob is not None:
             try:
                 from idre_clean.hive.utils import unpack_plaintext
             except Exception:
                 from hive.utils import unpack_plaintext
             ok_unpack, text = unpack_plaintext(bytes(blob))
             if ok_unpack:
                 self.received_messages.append(text)
                 
        return blob, reason, acks, tag



# Helper to satisfy IDRE v3 Vocab Requirement
def _get_dummy_vocab():
    try:
        from idre_clean.core.vocab_codec import Vocab
    except ImportError:
        from core.vocab_codec import Vocab
        
    tokens = ["<pad>", "<a>", "<b>", "<c>"]
    t2i = {t: i for i, t in enumerate(tokens)}
    return Vocab(tokens=tokens, token_to_index=t2i, vocab_id=b"DUMMY_STREAM", lens_by_first_char={})

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
        vocab=_get_dummy_vocab(),  # Mandatory for Vector Folding
        pepper="test_pepper",
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
