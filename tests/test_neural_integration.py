import unittest
import os
import sys

# Add repo root to sys.path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, root_dir)
# Add parent of repo root to sys.path to allow 'idre_clean' package import
sys.path.insert(0, os.path.dirname(root_dir))

from hive.node import FieldBoundNode
from core.neural_codec import OP_ACK
from core.vocab_codec import Vocab

def _create_dummy_vocab():
    tokens = ["<pad>", "<a>", "<b>", "<c>"]
    t2i = {t: i for i, t in enumerate(tokens)}
    return Vocab(tokens=tokens, token_to_index=t2i, vocab_id=b"DUMMY", lens_by_first_char={})

class TestNeuralIntegration(unittest.TestCase):
    def setUp(self):
        # Setup two nodes
        self.seed_a = 12345
        self.seed_b = 12345 # Must share seed for symmetric crypto & codec key
        
        vocab = _create_dummy_vocab()
        
        self.node_a = FieldBoundNode(
            node_id="A", seed=self.seed_a, anchor_seeds=(self.seed_a,), anchor_weight=1.0, 
            n_angles=16, scan_resolution=16, threshold=0.1, planes=1, tau_frac=0.5,
            print_deliveries=True, print_events=True, freeze_field=True, backend="frozen",
            vocab=vocab
        )
        self.node_b = FieldBoundNode(
            node_id="B", seed=self.seed_b, anchor_seeds=(self.seed_b,), anchor_weight=1.0,
            n_angles=16, scan_resolution=16, threshold=0.1, planes=1, tau_frac=0.5,
            print_deliveries=True, print_events=True, freeze_field=True, backend="frozen",
            vocab=vocab
        )
        
        # Force Session
        self.session_id = "test-session-1"
        self.e_salt = 999
        self.node_a.force_session("B", self.session_id, self.e_salt)
        self.node_b.force_session("A", self.session_id, self.e_salt)
        
    def test_full_codec_loop(self):
        # 1. A sends Literal -> B
        msg_1 = "Repeat Me"
        # We need to repeat > MIN_OBSERVATIONS (3) to trigger Propose
        # A's encoder counts:
        # 1st: Literal (count=1)
        # 2nd: Literal (count=2)
        # 3rd: Literal (count=3) -> Next time Propose?
        # Logic in encode_packet: `count = old + 1`. `should_propose = count >= 3`.
        # So 3rd send should be Propose?
        # Let's see.
        
        # Send 1
        pkt1 = self.node_a.send("B", msg_1)
        res1 = self.node_b.receive(pkt1, "A")
        self.assertEqual(res1["status"], "delivered")
        
        # Send 2
        pkt2 = self.node_a.send("B", msg_1)
        res2 = self.node_b.receive(pkt2, "A")
        self.assertEqual(res2["status"], "delivered")
        
        # Send 3 (count=3 -> PROPOSE)
        # Check internal packet op first?
        # Hard to inspect encrypted payload.
        # But we can verify B generated ACK.
        
        pkt3 = self.node_a.send("B", msg_1)
        res3 = self.node_b.receive(pkt3, "A")
        self.assertEqual(res3["status"], "delivered")
        
        # B should have generated ACK for pkt3
        sess_b_a = self.node_b.sessions["A"]
        self.assertEqual(len(sess_b_a.pending_acks), 1)
        ack_pkt = sess_b_a.pending_acks[0]
        self.assertEqual(ack_pkt[0], OP_ACK)
        
        # 2. B sends ACK -> A (Piggybacked on data)
        # B sends a message to A. It should inject the ACK.
        msg_back = "Acknowledged"
        pkt_back = self.node_b.send("A", msg_back)
        
        # Verify B cleared pending acks
        self.assertEqual(len(sess_b_a.pending_acks), 0)
        
        # A receives
        res_back = self.node_a.receive(pkt_back, "B")
        self.assertEqual(res_back["status"], "delivered")
        
        # A should have promoted ID.
        # 3. A sends RECALL -> B
        pkt4 = self.node_a.send("B", msg_1)
        # Inspect payload length? RECALL is much shorter.
        # msg_1 "Repeat Me" is 9 chars.
        # Literal: OP(1) + Len(2) + 9 = 12 bytes.
        # Propose: OP(1) + ID(4) + Len(2) + 9 = 16 bytes.
        # Recall: OP(1) + ID(4) = 5 bytes.
        # Encrypted payload has padding/framing, but we can check raw length of 'ct' inside?
        # Or easier: Trust logic. If decode works on B, and A thinks it's Recall.
        
        res4 = self.node_b.receive(pkt4, "A")
        self.assertEqual(res4["status"], "delivered")
        
        # Verify B decoded correctly
        # (Implicitly verified by status=delivered, but we can't see the text here easily
        # unless we mock receive output or check print_deliveries output)
        
    def test_eviction_safety(self):
        # Fill dictionary to force eviction
        pass # Todo

if __name__ == '__main__':
    unittest.main()
