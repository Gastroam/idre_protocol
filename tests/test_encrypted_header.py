"""Tests for Encrypted Headers and Rotating Route Tags."""

import os
import sys
import time
import unittest

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, root_dir)
sys.path.insert(0, os.path.dirname(root_dir))

from hive.protocol import derive_route_tag, encrypt_header, decrypt_header
from hive.node import FieldBoundNode
from core.vocab_codec import Vocab


def _create_dummy_vocab():
    tokens = ["<pad>", "<a>", "<b>", "<c>"]
    t2i = {t: i for i, t in enumerate(tokens)}
    return Vocab(tokens=tokens, token_to_index=t2i, vocab_id=b"DUMMY", lens_by_first_char={})


# Dummy field fingerprint bits
BITS_A = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1]
BITS_B = [0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0]


class TestRouteTag(unittest.TestCase):
    """Test route tag derivation properties."""

    def test_deterministic(self):
        """Same bits + epoch → same tag."""
        tag1 = derive_route_tag(BITS_A, epoch=100)
        tag2 = derive_route_tag(BITS_A, epoch=100)
        self.assertEqual(tag1, tag2)
        self.assertEqual(len(tag1), 16, "Route tag must be 16 bytes")

    def test_epoch_rotation(self):
        """Different epochs → different tags."""
        tag_e0 = derive_route_tag(BITS_A, epoch=100)
        tag_e1 = derive_route_tag(BITS_A, epoch=101)
        self.assertNotEqual(tag_e0, tag_e1)

    def test_wrong_bits(self):
        """Different bits → different tag. Cannot link."""
        tag_a = derive_route_tag(BITS_A, epoch=100)
        tag_b = derive_route_tag(BITS_B, epoch=100)
        self.assertNotEqual(tag_a, tag_b)


class TestHeaderEncryption(unittest.TestCase):
    """Test header encrypt/decrypt roundtrip."""

    def test_roundtrip(self):
        header = {
            "type": "DATA",
            "session_id": "test-session-1",
            "nonce": 12345678,
            "src_node_id": "A",
            "dst_node_id": "B",
        }
        enc = encrypt_header(header, BITS_A, "test-session-1", 12345678)
        self.assertIsInstance(enc, bytes)
        self.assertGreater(len(enc), 2, "Encrypted header must have length prefix + data")

        ok, decrypted = decrypt_header(enc, BITS_A, "test-session-1", 12345678)
        self.assertTrue(ok, "Decryption must succeed")
        self.assertEqual(decrypted, header)

    def test_wrong_bits_fails(self):
        """Encrypt with bits A, decrypt with bits B → fails."""
        header = {"type": "DATA", "session_id": "s1", "nonce": 1}
        enc = encrypt_header(header, BITS_A, "s1", 1)

        ok, decrypted = decrypt_header(enc, BITS_B, "s1", 1)
        self.assertFalse(ok, "Decryption with wrong bits must fail")
        self.assertEqual(decrypted, {})

    def test_wrong_nonce_fails(self):
        """Encrypt with nonce N, decrypt with nonce M → fails."""
        header = {"type": "DATA", "session_id": "s1", "nonce": 1}
        enc = encrypt_header(header, BITS_A, "s1", 1)

        ok, decrypted = decrypt_header(enc, BITS_A, "s1", 99999)
        self.assertFalse(ok, "Decryption with wrong nonce must fail")

    def test_truncated_data_fails(self):
        """Truncated encrypted header → fails gracefully."""
        ok, decrypted = decrypt_header(b"\x00", BITS_A, "s1", 1)
        self.assertFalse(ok)

        ok2, decrypted2 = decrypt_header(b"", BITS_A, "s1", 1)
        self.assertFalse(ok2)


class TestEndToEndEncryptedHeaders(unittest.TestCase):
    """Full send/receive with encrypted headers enabled."""

    def setUp(self):
        seed = 12345
        vocab = _create_dummy_vocab()
        self.node_a = FieldBoundNode(
            node_id="A", seed=seed, anchor_seeds=(seed,), anchor_weight=1.0,
            n_angles=16, scan_resolution=16, threshold=0.1, planes=1, tau_frac=0.5,
            print_deliveries=False, print_events=False, freeze_field=True, backend="frozen",
            vocab=vocab
        )
        self.node_b = FieldBoundNode(
            node_id="B", seed=seed, anchor_seeds=(seed,), anchor_weight=1.0,
            n_angles=16, scan_resolution=16, threshold=0.1, planes=1, tau_frac=0.5,
            print_deliveries=False, print_events=False, freeze_field=True, backend="frozen",
            vocab=vocab
        )
        self.session_id = "test-enc-hdr-1"
        self.e_salt = 42
        self.node_a.force_session("B", self.session_id, self.e_salt)
        self.node_b.force_session("A", self.session_id, self.e_salt)

    def test_send_receive_encrypted_header(self):
        """Full roundtrip with encrypted headers."""
        pkt = self.node_a.send("B", "Hello encrypted headers!", encrypt_headers=True)

        # Verify the wire format has encrypted header
        self.assertIn("encrypted_header", pkt)
        self.assertIn("route_tag", pkt)
        self.assertIn("payload", pkt)
        # Plaintext fields should NOT be present
        self.assertNotIn("type", pkt)
        self.assertNotIn("src_node_id", pkt)
        self.assertNotIn("dst_node_id", pkt)

        # Receive should auto-detect and decrypt
        result = self.node_b.receive(pkt, "A")
        self.assertEqual(result["status"], "delivered")

    def test_backward_compat_plaintext_header(self):
        """Legacy plaintext header still works."""
        pkt = self.node_a.send("B", "Hello plaintext headers!")
        
        # Verify old format
        self.assertIn("type", pkt)
        self.assertIn("src_node_id", pkt)
        self.assertNotIn("encrypted_header", pkt)

        result = self.node_b.receive(pkt, "A")
        self.assertEqual(result["status"], "delivered")

    def test_wrong_field_cannot_decrypt_header(self):
        """A node with different field config cannot decrypt the header."""
        pkt = self.node_a.send("B", "Secret message", encrypt_headers=True)

        # Create a node with a different seed (different field)
        vocab = _create_dummy_vocab()
        node_c = FieldBoundNode(
            node_id="C", seed=99999, anchor_seeds=(99999,), anchor_weight=1.0,
            n_angles=16, scan_resolution=16, threshold=0.1, planes=1, tau_frac=0.5,
            print_deliveries=False, print_events=False, freeze_field=True, backend="frozen",
            vocab=vocab
        )
        node_c.force_session("A", self.session_id, self.e_salt)

        result = node_c.receive(pkt, "A")
        self.assertEqual(result["status"], "reject")
        self.assertEqual(result["reason"], "header_decrypt_failed")


if __name__ == "__main__":
    unittest.main()
