
import unittest
import time
import copy
import sys
from pathlib import Path
from typing import List

# Fix Import Path
_REPO_ROOT = Path(__file__).resolve().parent.parent
# Add the PARENT of the repo so 'idre_clean' package resolves
if str(_REPO_ROOT.parent) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT.parent))
# Also add the repo root itself for direct imports if needed (legacy)
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Fallback for testing environment
try:
    from idre_clean.hive.node import FieldBoundNode
    from idre_clean.core.session import HiveSession, NonceWindow
    from idre_clean.core.neural_codec import NeuralCodec
    from idre_clean.hive.utils import canonical_json, pack_plaintext
    from idre_clean.hive.protocol import aad_with_epoch_anchor
except ImportError:
    from hive.node import FieldBoundNode
    from core.session import HiveSession, NonceWindow
    from core.neural_codec import NeuralCodec
    from hive.utils import canonical_json
    from hive.protocol import aad_with_epoch_anchor

class MockVocab:
    def __init__(self):
        self.tokenizer = {}
        self.detokenizer = {}

class TestMultiverse(unittest.TestCase):
    def _create_dummy_vocab(self):
        try:
            from idre_clean.core.vocab_codec import Vocab
        except ImportError:
            from core.vocab_codec import Vocab
        return Vocab(["a"], {"a": 0}, b"dummy", {})

    def setUp(self):
        self.node = FieldBoundNode(
            node_id="NODE_A",
            seed=1234,
            healing_mode="multiverse",
            print_events=True,
            # Mandatory args
            anchor_seeds=(7245,),
            anchor_weight=80.0,
            n_angles=72,
            scan_resolution=50,
            threshold=0.5,
            planes=4,
            tau_frac=0.55,
            print_deliveries=False,
            freeze_field=True,
            backend="frozen",
            vocab=self._create_dummy_vocab(),
        )
        # Manually inject a session
        self.peer_id = "PEER_B"
        self.session_id = "sess_001"
        self.codec = NeuralCodec(session_key=b"0"*32)
        
        # Initial Session (Timeline A)
        self.sess_a = HiveSession(
            session_id=self.session_id,
            peer_id=self.peer_id,
            start_time=time.time(),
            ttl_s=60.0,
            ephemeral_salt=100,
            # Use INT for ratchet key
            ratchet_key=111111, 
            chain_hash=b"HASH_A",
            codec=self.codec,
            seen=NonceWindow(capacity=32)
        )
        self.node.timelines[self.peer_id] = [self.sess_a]

    def test_multiverse_collapse(self):
        """
        Verify that if we have 2 timelines, and a packet matches Timeline B,
        we accept it and prune Timeline A (Collapse).
        """
        # Create Timeline B (Clone and Diverge)
        sess_b = self.sess_a.clone()
        sess_b.ratchet_key = 222222 # Diverged Key (INT)
        
        # Register both (Ambiguous State)
        self.node.timelines[self.peer_id].append(sess_b)
        self.assertEqual(len(self.node.timelines[self.peer_id]), 2)
        
        # Prepare a packet encrypted with KEY_B (sess_b)
        # We use Node to encrypt it using a temporary session equivalent to B
        # But we need to pretend we are PEER_B sending to NODE_A.
        
        # Helper to encrypt
        payload = list(pack_plaintext("ABC")) 
        header = {
            "type": "DATA",
            "field_profile_id": self.node.field_profile_id,
            "session_id": self.session_id,
            "nonce": 5,
            "created_at_ms": int(time.time()*1000),
            "expires_at_ms": int(time.time()*1000) + 5000,
            "src_node_id": self.peer_id,
            "dst_node_id": "NODE_A",
            "hop_count": 0,
            "max_hops": 5
        }
        
        # Encrypt using SESS_B params
        aad = canonical_json(header)
        # Note: In receive, we add epoch anchor to aad.
        # But send() adds it inside encrypt_packet? No, decrypt_bytes checks it.
        # We need to constructing the ciphertext manually or use helper.
        # Let's use node.encrypt_packet (stateless-ish logic?)
        # node.encrypt_payload uses self.sessions.
        
        # We manually call _encrypt_aead from somewhere? No, internal.
        # We use a temporary node representing Peer B
        node_b = FieldBoundNode(
            node_id="PEER_B", 
            seed=9999,
            # Mandatory args
            anchor_seeds=(7245,),
            anchor_weight=80.0,
            n_angles=72,
            scan_resolution=50,
            threshold=0.5,
            planes=4,
            tau_frac=0.55,
            print_deliveries=False,
            print_events=True,
            freeze_field=True,
            backend="frozen",
            vocab=self._create_dummy_vocab(),
        )
        sess_b_peer = sess_b.clone() 
        # But swap implicit direction? No, shared key.
        node_b.timelines["NODE_A"] = [sess_b_peer]
        
        # Encrypt packet from B -> A
        # We use `encrypt_payload` or low level
        # Let's use `encrypt_bytes` if exposed? No.
        # Use `send` logic simulation
        from idre_clean.hive.protocol import aad_with_epoch_anchor
        aad_full = aad_with_epoch_anchor(aad, chain_hash=sess_b.chain_hash, seq=sess_b.out_seq + 1)
        
        ct_blob, tag = node_b.encrypt_bytes(
            plaintext=bytes(payload),
            session_id=self.session_id,
            nonce=header["nonce"],
            ephemeral_salt=sess_b.ephemeral_salt,
            aad=aad_full,
            codec=sess_b.codec,
            ratchet_key=sess_b.ratchet_key
        )
        
        # Construct Wire Message
        msg = copy.deepcopy(header)
        msg["payload"] = list(ct_blob) + list(tag)
        
        # --- EXECUTE RECEIVE on NODE A ---
        res = self.node.receive(msg, prev_hop_id=self.peer_id)
        
        # --- VERIFY ---
        self.assertEqual(res["status"], "delivered")
        
        # Check Collapse: Should only have 1 timeline now (The Winner: Sess B)
        timelines = self.node.timelines[self.peer_id]
        self.assertEqual(len(timelines), 1, "Should have collapsed to 1 timeline")
        self.assertEqual(timelines[0].ratchet_key, 222222)
        print("Multiverse Collapse Verified!")

if __name__ == "__main__":
    unittest.main()
