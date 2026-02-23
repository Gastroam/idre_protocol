import unittest
import logging
import time
import os
import sys

# Fix Path for idre_clean package resolution
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
if root_dir not in sys.path:
    sys.path.append(root_dir)
parent_dir = os.path.dirname(root_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from hive.node import FieldBoundNode, canonical_json
from core.session import HiveSession
from core.vocab_codec import Vocab
import struct

def _create_dummy_vocab():
    tokens = ["<pad>", "<a>", "<b>", "<c>"]
    t2i = {t: i for i, t in enumerate(tokens)}
    return Vocab(tokens=tokens, token_to_index=t2i, vocab_id=b"DUMMY", lens_by_first_char={})

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger("TestResilience")

class TestResilience(unittest.TestCase):
    def setUp(self):
        # 1. Initialize Nodes with Shared Pepper
        cluster_pepper = b"Resilience_Test_Pepper"
        vocab = _create_dummy_vocab()
        
        self.node_a = FieldBoundNode(node_id="A (Sender)", seed=111, anchor_seeds=(111,), anchor_weight=80.0,
            n_angles=72, scan_resolution=50, threshold=0.5, planes=4, tau_frac=0.55,
            print_deliveries=True, print_events=True, freeze_field=True, backend="frozen",
            pepper=cluster_pepper,
            vocab=vocab
        )
        self.node_b = FieldBoundNode(node_id="B (Receiver)", seed=222, anchor_seeds=(222,), anchor_weight=80.0,
            n_angles=72, scan_resolution=50, threshold=0.5, planes=4, tau_frac=0.55,
            print_deliveries=True, print_events=True, freeze_field=True, backend="frozen",
            pepper=cluster_pepper,
            vocab=vocab
        )
        
        # 2. Force Session
        sess_id = "SESS_RESILIENCE"
        # Manually sync keys for test simplicity
        shared_k = 123456789
        
        self.node_a.timelines[self.node_b.node_id] = [HiveSession(
            session_id=sess_id, peer_id=self.node_b.node_id, start_time=time.time(),
            ratchet_key=shared_k, ephemeral_salt=999
        )]
        self.node_b.timelines[self.node_a.node_id] = [HiveSession(
            session_id=sess_id, peer_id=self.node_a.node_id, start_time=time.time(),
            ratchet_key=shared_k, ephemeral_salt=999
        )]
        
        # Align field geometry / codec
        dummy_field = [0] * 1024
        self.node_a._cached_bits = dummy_field
        self.node_b._cached_bits = dummy_field
        
        # Share codec (A -> B)
        # We need a dummy NeuralCodec or just assume None/Default if backend="frozen"
        # Frozen backend uses "field" logic but codec is for compression.
        # Let's ensure they match.
        self.node_b.timelines[self.node_a.node_id][0].codec = self.node_a.timelines[self.node_b.node_id][0].codec
        
        # 3. Align Consensus Anchor (last_ratchet_hash)
        # Note: Code now uses `last_ratchet_hash` in AAD.
        # Default is empty string?
        # Let's set a shared anchor
        anchor = "0xGenesisBlock"
        self.current_anchor = anchor.encode()
        self.node_a.timelines["B (Receiver)"][0].chain_hash = self.current_anchor
        self.node_b.timelines["A (Sender)"][0].chain_hash = self.current_anchor

    def test_packet_loss_recovery(self):
        logger.info("--- Testing Packet Loss Recovery (Windowed) ---")
        
        # Helper to construct MSG dict & Send
        def send_receive(seq_num, text, expect_success=True):
            # 1. Construct AAD (Server side logic)
            # AAD = Header + BlockHash + Seq
            header = {
                "type": "DATA",
                "field_profile_id": str(getattr(self.node_b, "field_profile_id", "")),
                "session_id": "SESS_RESILIENCE",
                "nonce": seq_num * 100, # Just using seq as nonce base
                "created_at_ms": int(time.time() * 1000),
                "expires_at_ms": int((time.time() + 600) * 1000),
                "src_node_id": "A (Sender)",
                "dst_node_id": "B (Receiver)",
                "hop_count": 0,
                "max_hops": 0
            }
            aad_base = canonical_json(header)
            aad = aad_base + self.current_anchor + struct.pack(">Q", seq_num)
            
            # 2. Encrypt
            payload, tag = self.node_a.encrypt_message(
                text, 
                session_id="SESS_RESILIENCE", 
                nonce=seq_num * 100, 
                ephemeral_salt=999, 
                ratchet_key=123456789,
                aad=aad
            )
            
            # Update Anchor (Chain Hash Simulation) if we expect this to succeed/be processed
            # Sender ignores update for dropped packets manually?
            # Test logic:
            if expect_success:
                 import hashlib
                 # Protocol Update: chain_hash = H(chain_hash + seq)
                 # Wait, did we change valid update logic in NODE?
                 # Yes, in hive/node.py we changed `update_chain_hash(chain_hash, seq)`
                 # So we must replicate that here for the test helper!
                 self.current_anchor = hashlib.sha256(self.current_anchor + struct.pack(">Q", seq_num)).digest()
            
            # 3. Receive
            msg = header.copy()
            msg["payload"] = payload
            
            res = self.node_b.receive(msg, prev_hop_id="A (Sender)")
            status = res["status"]
            
            if expect_success:
                self.assertEqual(status, "delivered", f"Seq {seq_num} failed! Reason: {res.get('reason')}")
            else:
                self.assertNotEqual(status, "delivered", f"Seq {seq_num} should have failed!")

        # Step 1: Normal (Seq 1)
        # Initial in_seq = 0. Expects 1.
        send_receive(1, "Msg 1 - Baseline")
        self.assertEqual(self.node_b.timelines["A (Sender)"][0].in_seq, 1)
        logger.info("[Pass] Seq 1 delivered.")
        
        # Step 2: Skip Seq 2 (Simulate Packet Loss)
        # Send Seq 3.
        # Current in_seq = 1. Expects 2.
        # Window: [2, 3, 4, 5, 6, 7]
        # Seq 3 is inside window.
        logger.info("--- Dropping Seq 2, Sending Seq 3 ---")
        send_receive(3, "Msg 3 - Gap Check")
        self.assertEqual(self.node_b.timelines["A (Sender)"][0].in_seq, 3)
        logger.info("[Pass] Seq 3 delivered. Gap 2 skipped.")
        
        # Step 3: Massive Gap (Seq 10)
        # Current in_seq = 3. Expects 4.
        # Window: [4, 5, 6, 7, 8, 9] (Size 5: 4,5,6,7,8,9)
        # Seq 10 is OUTSIDE window.
        logger.info("--- Sending Seq 10 (Outside Window) ---")
        send_receive(10, "Msg 10 - Too Far", expect_success=False)
        self.assertEqual(self.node_b.timelines["A (Sender)"][0].in_seq, 3) # Should not advance
        logger.info("[Pass] Seq 10 rejected.")
        
        # Step 4: Window Edge (Seq 8)
        # Expects 4. 
        # Window 5 -> range(6) -> offsets 0..5 -> seqs 4..9.
        # Seq 8 is inside.
        logger.info("--- Sending Seq 8 (Inside Window) ---")
        send_receive(8, "Msg 8 - Edge")
        self.assertEqual(self.node_b.timelines["A (Sender)"][0].in_seq, 8)
        logger.info("[Pass] Seq 8 accepted.")

if __name__ == "__main__":
    unittest.main()
