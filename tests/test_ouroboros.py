
import unittest
import os
import sys
import time

# Add repo root to sys.path
# We need to add the PARENT of idre_clean to sys.path to import idre_clean.xxx
# idre_clean is at f:\idre_clean.
# So we need to add f:\ to sys.path?
# Or if idre_clean is a package inside f:\idre_clean\idre_clean?
# The structure is f:\idre_clean\hive\node.py using `from idre_clean.core...`
# This implies `idre_clean` IS a package.
# So `f:\` must be in sys.path.
sys.path.append("f:\\")
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from hive.node import FieldBoundNode

class TestOuroboros(unittest.TestCase):
    def setUp(self):
        # Setup two nodes with same seed
        self.seed = 8888
        self.node_a = FieldBoundNode(
            node_id="A", seed=self.seed, anchor_seeds=(self.seed,), anchor_weight=1.0, 
            n_angles=16, scan_resolution=16, threshold=0.1, planes=1, tau_frac=0.5,
            print_deliveries=False, print_events=False, freeze_field=True, backend="frozen"
        )
        self.node_b = FieldBoundNode(
            node_id="B", seed=self.seed, anchor_seeds=(self.seed,), anchor_weight=1.0,
            n_angles=16, scan_resolution=16, threshold=0.1, planes=1, tau_frac=0.5,
            print_deliveries=False, print_events=False, freeze_field=True, backend="frozen"
        )
    
    def test_ratchet_flow(self):
        # 1. Establish Session
        sid = "ouroboros-1"
        salt = 777
        self.node_a.force_session("B", sid, salt)
        self.node_b.force_session("A", sid, salt)
        
        sess_a = self.node_a.sessions["B"]
        sess_b = self.node_b.sessions["A"]
        
        print(f"Node A Profile: {self.node_a.field_profile_id}")
        print(f"Node B Profile: {self.node_b.field_profile_id}")

        # Verify Ratchet Key Initialization
        self.assertIsNotNone(sess_a.ratchet_key)
        self.assertIsNotNone(sess_b.ratchet_key)
        self.assertEqual(sess_a.ratchet_key, sess_b.ratchet_key, "Initial ratchet keys must match")
        self.assertNotEqual(sess_a.ratchet_key, self.seed, "Ratchet key must derived, not raw seed")
        
        # 2. Exchange Message (Pre-Ratchet)
        pkt1 = self.node_a.send("B", "Message 1 (Genesis)")
        res1 = self.node_b.receive(pkt1, "A")
        if res1["status"] != "delivered":
            print(f"Msg 1 Failed: {res1}")
        self.assertEqual(res1["status"], "delivered")
        
        # 3. Trigger Ouroboros (Consensus Event)
        block_hash = "0xdeadbeef" * 8 # 64 chars
        print("\n\n--- INGESTING BLOCK 1 ---")
        self.node_a.ingest_finalized_block(block_hash)
        self.node_b.ingest_finalized_block(block_hash)
        
        # Verify Key Rotation
        self.assertNotEqual(sess_a.ratchet_key, self.seed)
        self.assertEqual(sess_a.ratchet_key, sess_b.ratchet_key, "Keys must match after synchronous ratchet")
        self.assertEqual(sess_a.last_ratchet_hash, block_hash)
        
        # 4. Exchange Message (Post-Ratchet)
        pkt2 = self.node_a.send("B", "Message 2 (Ratcheted)")
        res2 = self.node_b.receive(pkt2, "A")
        self.assertEqual(res2["status"], "delivered")
        
    def test_ratchet_divergence(self):
        # 1. Establish
        sid = "ouroboros-div"
        salt = 888
        self.node_a.force_session("B", sid, salt)
        self.node_b.force_session("A", sid, salt)
        
        # 2. Diverge!
        # Node A sees Reality A
        self.node_a.ingest_finalized_block("0xREALITY_A")
        # Node B sees Reality B (Clone Attack / Fork)
        self.node_b.ingest_finalized_block("0xREALITY_B")
        
        self.assertNotEqual(self.node_a.sessions["B"].ratchet_key, self.node_b.sessions["A"].ratchet_key)
        
        # 3. Attempt Communication
        pkt = self.node_a.send("B", "Message 3 (Diverged)")
        res = self.node_b.receive(pkt, "A")
        
        # Should Fail (MAC Mismatch due to different keys)
        self.assertEqual(res["status"], "reject")
        self.assertIn(res["reason"], ["mac_mismatch", "bad_plaintext", "unpack_error"], "Must reject if keys diverged")

if __name__ == '__main__':
    unittest.main()
