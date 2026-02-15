
import unittest
import os
import sys
import struct
import hashlib
from typing import Dict, Any

# Add repo root to sys.path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, root_dir)
sys.path.insert(0, os.path.dirname(root_dir))

from hive.node import FieldBoundNode
from hive.crypto import derive_mac_key

class TestProtocolInvariants(unittest.TestCase):
    def setUp(self):
        # Setup two nodes with same seed
        self.seed = 12345
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
        # Force Session
        self.session_id = "test-inv-1"
        self.e_salt = 999
        self.node_a.force_session("B", self.session_id, self.e_salt)
        self.node_b.force_session("A", self.session_id, self.e_salt)

    def test_monotonic_chain_index(self):
        """Invariant: Sequence number must increment strictly."""
        # A sends 1
        pkt1 = self.node_a.send("B", "Msg 1")
        res1 = self.node_b.receive(pkt1, "A")
        self.assertEqual(res1["status"], "delivered")
        
        # Check Sequence State
        self.assertEqual(self.node_a.sessions["B"].out_seq, 1)
        self.assertEqual(self.node_b.sessions["A"].in_seq, 1)

        # A sends 2
        pkt2 = self.node_a.send("B", "Msg 2")
        # Sanity Check
        res2 = self.node_b.receive(pkt2, "A")
        self.assertEqual(res2["status"], "delivered")
        self.assertEqual(self.node_b.sessions["A"].in_seq, 2)

        # Drop 3, Send 4 (Strict Sequencing should REJECT)
        self.node_a.send("B", "Msg 3 (Dropped)") # out_seq=3
        pkt4 = self.node_a.send("B", "Msg 4")       # out_seq=4
        res4 = self.node_b.receive(pkt4, "A")
        self.assertEqual(res4["status"], "reject", "Must reject out-of-order packet")
        self.assertEqual(res4["reason"], "mac_mismatch", "AAD mismatch causes MAC failure")
        self.assertEqual(self.node_b.sessions["A"].in_seq, 2, "in_seq must not advance")

    def test_no_plasticity_on_replay(self):
        """Invariant: Replay must be rejected BEFORE plasticity (lattice evolution)."""
        # Enable plasticity tracking (mock _evolve_lattice)
        original_evolve = self.node_b._evolve_lattice
        self.evolve_calls = 0
        def mock_evolve(seed):
            self.evolve_calls += 1
            return original_evolve(seed)
        self.node_b._evolve_lattice = mock_evolve

        # Valid Packet
        pkt = self.node_a.send("B", "Plasticity Test")
        res = self.node_b.receive(pkt, "A")
        self.assertEqual(res["status"], "delivered")
        self.assertEqual(self.evolve_calls, 1, "Should evolve once on valid packet")

        # Replay Packet
        res_replay = self.node_b.receive(pkt, "A")
        self.assertEqual(res_replay["status"], "reject")
        self.assertEqual(res_replay["reason"], "replay")
        self.assertEqual(self.evolve_calls, 1, "Should NOT evolve on replay")

    def test_no_plasticity_on_auth_fail(self):
        """Invariant: Auth failure must be rejected BEFORE plasticity."""
        # Enable plasticity tracking
        original_evolve = self.node_b._evolve_lattice
        self.evolve_calls = 0
        def mock_evolve(seed):
            self.evolve_calls += 1
            return original_evolve(seed)
        self.node_b._evolve_lattice = mock_evolve

        # Send packet with WRONG KEY (tampered payload)
        pkt = self.node_a.send("B", "Valid message")
        # Tamper payload (flip last byte of tag/ciphertext)
        # payload is list[int].
        pkt["payload"][-1] ^= 0xFF 
        
        res = self.node_b.receive(pkt, "A")
        self.assertEqual(res["status"], "reject")
        # Could be mac_mismatch or framing_error depending on where we hit.
        # But crucially:
        self.assertEqual(self.evolve_calls, 0, "Should NOT evolve on auth failure")

    def test_receiver_state_binding(self):
        """Invariant: Packet must bind to receiver's chain hash."""
        # Sync
        self.node_a.send("B", "Sync 1")
        pkt = self.node_a.send("B", "Bound Message")
        self.node_b.receive(pkt, "A") # Desync B by not delivering Sync 1? No, deliver pkt1 first.
        # Wait, let's manually desync B's chain hash.
        
        # Reset
        self.setUp()
        
        # A sends 1
        pkt1 = self.node_a.send("B", "Msg 1")
        # B *skips* 1? No, then seq mismatch.
        # B receives 1, but we tamper B's state.
        res1 = self.node_b.receive(pkt1, "A")
        self.assertEqual(res1["status"], "delivered")
        
        # Tamper B's chain hash
        self.node_b.sessions["A"].chain_hash = b"\x00" * 32
        
        # A sends 2
        pkt2 = self.node_a.send("B", "Msg 2")
        res2 = self.node_b.receive(pkt2, "A")
        self.assertEqual(res2["status"], "reject")
        self.assertEqual(res2["reason"], "mac_mismatch", "Must reject if chain hash mismatches")

if __name__ == '__main__':
    unittest.main()
