
import unittest
import logging
import sys
import os

# Add repo root to path
# We need to add 'f:\idre_clean' (or whatever the root is) to sys.path
# stored in current_dir/..
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
if root_dir not in sys.path:
    sys.path.append(root_dir)

# Also need parent of root for 'idre_clean' package resolution if it expects that structure
# But usually if we are in f:\idre_clean, import hive works.
# But 'from idre_clean.core...' requires 'idre_clean' to be a package in path?
# No, 'idre_clean' is likely the Repo Root, but unless there is an __init__.py at root, it's not a package?
# Actually node.py does `from idre_clean.core...` so it expects `idre_clean` to be importable.
# This means the directory CONTAINER of `idre_clean` must be in path.
# So we need `root_dir/..`
parent_dir = os.path.dirname(root_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from hive.node import FieldBoundNode
from core.vocab_codec import Vocab

def _create_dummy_vocab():
    tokens = ["<pad>", "<a>", "<b>", "<c>"]
    t2i = {t: i for i, t in enumerate(tokens)}
    return Vocab(tokens=tokens, token_to_index=t2i, vocab_id=b"DUMMY", lens_by_first_char={})

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger("ShatteredGlass")

class TestShatteredGlass(unittest.TestCase):

    def setUp(self):
        # 1. Initialize the Hive
        # Shared Cluster Secret (Pepper) allows Ratchet Sync
        # If Pepper differs, Ratchet Keys diverge immediately on first block.
        cluster_pepper = b"Shared_Hive_Secret_v1"
        vocab = _create_dummy_vocab()
        
        # Node A: The Mainnet Anchor
        self.node_a = FieldBoundNode(
            node_id="A (Anchor)", seed=111111, anchor_seeds=(111111,), anchor_weight=80.0,
            n_angles=72, scan_resolution=50, threshold=0.5, planes=4, tau_frac=0.55,
            print_deliveries=False, print_events=False, freeze_field=True, backend="frozen",
            pepper=cluster_pepper,
            vocab=vocab
        )
        
        # Node B: The Node destined to Fork (The Clone)
        self.node_b = FieldBoundNode(
            node_id="B (Clone)", seed=222222, anchor_seeds=(222222,), anchor_weight=80.0,
            n_angles=72, scan_resolution=50, threshold=0.5, planes=4, tau_frac=0.55,
            print_deliveries=False, print_events=False, freeze_field=True, backend="frozen",
            pepper=cluster_pepper,
            vocab=vocab
        )
        
        # Node C: The Control Group (Stays with A)
        self.node_c = FieldBoundNode(
            node_id="C (Loyal)", seed=333333, anchor_seeds=(333333,), anchor_weight=80.0,
            n_angles=72, scan_resolution=50, threshold=0.5, planes=4, tau_frac=0.55,
            print_deliveries=False, print_events=False, freeze_field=True, backend="frozen",
            pepper=cluster_pepper,
            vocab=vocab
        )

        # 2. Establish Sessions (Manually forced for test speed)
        self._force_handshake(self.node_a, self.node_b, "SESS_AB")
        self._force_handshake(self.node_a, self.node_c, "SESS_AC")

        # Confirm Initial State
        self.assertIsNotNone(self.node_a.sessions["B (Clone)"].ratchet_key)
        self.assertIsNotNone(self.node_b.sessions["A (Anchor)"].ratchet_key)
        
        # Keys match initially?
        # Note: force_session derives ratchet_key from Root Seed + SessionID.
        # Since seeds differ, we must ensure they agree on a shared secret or use the handshake flow.
        # Actually, force_session uses self.seed. So they will NOT match if we use force_session naively unless we override.
        # But wait, in Ouroboros, the handshake derives a SHARED key usually? 
        # No, in current default `process_verify_req`, ratchet_key is derived from SELF seed.
        # This implies ratchet_key is symmetric? NO. 
        # Wait, if A uses K_A and B uses K_B, they can't talk.
        # Let's check `process_verify_req`. It sets `ratchet_key = self._kdf(self.seed, "INIT::" + session_id)`.
        # This means A uses K_A and B uses K_B. But they need to SHARE a key for encryption?
        # `encrypt_message` uses `ratchet_key` if present.
        # If A encrypts with K_A, B must decrypt with K_A?
        # But B only has K_B.
        # AH! Currently Ouroboros implementation in `node.py` derives Ratchet Key from LOCAL Root Seed.
        # If Root Seeds differ, Ratchet Keys differ.
        # Does the current implementation support Diffie-Hellman? No.
        # It relies on `fingerprint_bits` which are Field-Bound.
        # If Field-Bound Auth works, it implies they share the field (or parts of it).
        # BUT here seeds are 111111 vs 222222.
        # UNLESS they are in the same "Field" (e.g. sharing reference vectors?).
        # Idre v1 relied on "Symmetric Seed" (PSK) or "Vector Field Alignment".
        # If nodes have DIFFERENT seeds, they have DIFFERENT fields.
        # So they can't communicate encoded content unless they negotiate a shared key.
        # The current `node.py` assumes Symmetric Seed for these tests usually.
        # Let's fix the test to use SYMMETRIC SEEDS as per typical IDRE clusters, 
        # OR manually sync the ratchet keys to simulate a completed DH exchange.
        
        # For this test, we will assume a "Cluster" where they share the root seed (Field Identity) 
        # but have distinct Node IDs.
        # Or we act as if they performed DH. 
        # Let's simple use SAME SEED for all to ensure they start synced.
        # The User's example had different seeds. 
        # If they have different seeds, `fingerprint_bits` won't align.
        # Let's Override Seeds to be same for the purpose of Transport Sync.
        
        # Actually, let's just manually set the ratchet_key to a shared value after init.
        # This simulates the result of a successful handshake establishing a shared secret.
        shared_k = 999999999
        self.node_a.sessions["B (Clone)"].ratchet_key = shared_k
        self.node_b.sessions["A (Anchor)"].ratchet_key = shared_k
        
        self.node_a.sessions["C (Loyal)"].ratchet_key = shared_k
        self.node_c.sessions["A (Anchor)"].ratchet_key = shared_k
        
        # Align Codecs (Since seeds differ, default codecs mismatch)
        # We use A's codec as the "Shared Truth"
        shared_codec = self.node_a.sessions["B (Clone)"].codec
        self.node_b.sessions["A (Anchor)"].codec = shared_codec
        self.node_c.sessions["A (Anchor)"].codec = shared_codec
        self.node_a.sessions["C (Loyal)"].codec = shared_codec

        # Calibrate Field Geometry (Target Length for Ratchet Bits)
        # Since seeds differ, natural field length differs, causing Modulo Mismatch in keystream.
        # We force them to agree on the "Physics Constant" (Bit Length) for this test.
        # This simulates nodes operating in a compatible Lattice Field.
        dummy_field_bits = [0] * 1024 # Length 1024
        self.node_a._cached_bits = dummy_field_bits
        self.node_b._cached_bits = dummy_field_bits
        self.node_c._cached_bits = dummy_field_bits

        logger.info("[✓] Pre-Fork: All systems nominal. Sessions Synced (Shared Ratchet Key & Codec & Field Geometry).")

    def _force_handshake(self, node1, node2, session_id):
        # Manually inject sessions
        salt = 12345
        node1.force_session(node2.node_id, session_id, salt)
        node2.force_session(node1.node_id, session_id, salt)

    def test_fork_divergence(self):
        """
        Simulates a network partition where Node B sees a different block hash than A and C.
        """
        
        # --- PHASE 1: THE COMMON REALITY (Block 100) ---
        block_100_hash = "0xaa11aa11aa11aa11" # The "True" Block
        
        logger.info(f"\n[*] PHASE 1: Consensus Reached on Block 100 ({block_100_hash})")
        self.node_a.ingest_finalized_block(block_100_hash)
        self.node_b.ingest_finalized_block(block_100_hash)
        self.node_c.ingest_finalized_block(block_100_hash)
        
        # TEST: A sends message to B
        aad_1 = b"Protocol_Header_1"
        payload, _ = self.node_a.encrypt_message(
            "Payload_1_Common_Reality", 
            session_id="SESS_AB", nonce=1, ephemeral_salt=123,
            ratchet_key=self.node_a.sessions["B (Clone)"].ratchet_key,
            aad=aad_1
        )
        
        # B attempts to decrypt
        ok, text, _, _ = self.node_b.decrypt_message(
            payload, 
            session_id="SESS_AB", nonce=1, ephemeral_salt=123,
            ratchet_key=self.node_b.sessions["A (Anchor)"].ratchet_key,
            aad=aad_1
        )
        self.assertTrue(ok)
        self.assertEqual(text, "Payload_1_Common_Reality")
        logger.info("[✓] Phase 1: Communication Secure. Keys aligned.")

        
        # --- PHASE 2: THE SHATTER (Block 101 - The Fork) ---
        block_101_TRUE = "0xbb22bb22bb22bb22"  # Mainnet Hash
        block_101_FAKE = "0xdeadbeefdeadbeef"  # Fork/Clone Hash
        
        logger.info("\n[!] PHASE 2: THE SHATTER EVENT.")
        logger.info(f"    Node A & C witness True Reality: {block_101_TRUE}")
        logger.info(f"    Node B witnesses False Reality:  {block_101_FAKE}")
        
        # A and C ingest the True Block
        self.node_a.ingest_finalized_block(block_101_TRUE)
        self.node_c.ingest_finalized_block(block_101_TRUE)
        
        # B ingests the Clone Block
        self.node_b.ingest_finalized_block(block_101_FAKE)
        
        # VERIFY KEY DIVERGENCE
        key_a = self.node_a.sessions["B (Clone)"].ratchet_key
        key_b = self.node_b.sessions["A (Anchor)"].ratchet_key
        logger.info(f"    Key A (Main): {str(key_a)[:10]}...")
        logger.info(f"    Key B (Fork): {str(key_b)[:10]}...")
        
        self.assertNotEqual(key_a, key_b, "CRITICAL FAIL: Keys should have diverged!")
        logger.info("[✓] Ouroboros Triggered: Keys have bifurcated.")

        
        # --- PHASE 3: THE BLACKOUT (Communication Attempt) ---
        logger.info("\n[?] PHASE 3: Testing Isolation.")
        
        # TEST 1: A talks to C (Should still work)
        aad_2 = b"Protocol_Header_2"
        payload_ac, _ = self.node_a.encrypt_message(
            "Payload_2_Still_Friends", 
            session_id="SESS_AC", nonce=2, ephemeral_salt=123,
            ratchet_key=self.node_a.sessions["C (Loyal)"].ratchet_key,
            aad=aad_2
        )
        ok_ac, text_ac, _, _ = self.node_c.decrypt_message(
            payload_ac, 
            session_id="SESS_AC", nonce=2, ephemeral_salt=123,
            ratchet_key=self.node_c.sessions["A (Anchor)"].ratchet_key,
            aad=aad_2
        )
        self.assertTrue(ok_ac)
        self.assertEqual(text_ac, "Payload_2_Still_Friends")
        logger.info("[✓] A <-> C Connection: ALIVE (Same Timeline)")

        # TEST 2: A talks to B (Should FAIL)
        aad_3 = b"Protocol_Header_3"
        payload_ab, _ = self.node_a.encrypt_message(
            "Payload_3_Are_You_There", 
            session_id="SESS_AB", nonce=3, ephemeral_salt=123,
            ratchet_key=self.node_a.sessions["B (Clone)"].ratchet_key,
            aad=aad_3
        )
        
        # B attempts to decrypt
        # Expectation: MAC mismatch or decryption gibberish
        ok_ab, text_ab, _, tag = self.node_b.decrypt_message(
            payload_ab, 
            session_id="SESS_AB", nonce=3, ephemeral_salt=123,
            ratchet_key=self.node_b.sessions["A (Anchor)"].ratchet_key,
            aad=aad_3
        )
        
        if ok_ab and text_ab == "Payload_3_Are_You_There":
             self.fail("SECURITY BREACH: Node B decrypted the message despite being on a fork!")
        else:
             logger.info(f"[✓] A -> B Connection: REJECTED (Stat: {ok_ab})")

        
        # --- PHASE 4: THE RESISTANCE (Replay Attack) ---
        # B tries to replay the message from Phase 1 (valid signature, old key)
        # But A has already ratcheted forward.
        logger.info("\n[?] PHASE 4: Testing Forward Secrecy.")
        # Node A receives OLD payload (Phase 1)
        # Note: We need to use 'receive' loop usually, but here we call decrypt_message directly.
        # A's key has rotated. Old payload used Old Key.
        # Should fail.
        
        # Re-using payload from Phase 1. 
        # A encrypts. A ratchets. A decrypts OLD payload.
        # We need to construct the call.
        
        ok_replay, text_replay, _, _ = self.node_a.decrypt_message(
             payload, # Phase 1 payload
             session_id="SESS_AB", nonce=1, ephemeral_salt=123,
             ratchet_key=self.node_a.sessions["B (Clone)"].ratchet_key, # NEW KEY
             aad=aad_1 # Phase 1 AAD
        )
        
        if ok_replay and text_replay == "Payload_1_Common_Reality":
             self.fail("SECURITY BREACH: Replay of old message accepted!")
        else:
             logger.info("[✓] Replay Attack: BLOCKED (Key Rotation)")

if __name__ == "__main__":
    unittest.main()
