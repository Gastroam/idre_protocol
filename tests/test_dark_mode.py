"""Tests for Dark Mode — Gatekeeper SPA (Single Packet Authorization)."""

import os
import sys
import time
import unittest

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, root_dir)
sys.path.insert(0, os.path.dirname(root_dir))

from hive.knock import create_knock, verify_knock, derive_knock_key, KNOCK_LEN
from hive.gatekeeper import UDPGatekeeper


# Dummy field fingerprint bits for testing
TEST_BITS = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1]


class TestKnockRoundtrip(unittest.TestCase):
    """Test that a valid knock is accepted."""

    def test_knock_roundtrip(self):
        epoch = int(time.time()) // 60
        knock = create_knock(TEST_BITS, epoch=epoch)
        self.assertEqual(len(knock), KNOCK_LEN, "Knock must be exactly 55 bytes")

        valid, reason = verify_knock(knock, TEST_BITS, epoch=epoch)
        self.assertTrue(valid, f"Valid knock rejected: {reason}")
        self.assertEqual(reason, "")


class TestInvalidKnockRejected(unittest.TestCase):
    """Test that garbage bytes are rejected."""

    def test_garbage_rejected(self):
        garbage = b"\x00" * KNOCK_LEN
        valid, reason = verify_knock(garbage, TEST_BITS)
        self.assertFalse(valid)
        self.assertIn(reason, ("bad_magic", "bad_tag", "expired"))

    def test_wrong_length_rejected(self):
        valid, reason = verify_knock(b"too short", TEST_BITS)
        self.assertFalse(valid)
        self.assertEqual(reason, "bad_length")


class TestExpiredKnockRejected(unittest.TestCase):
    """Test that a knock with an old timestamp is rejected."""

    def test_expired_knock(self):
        epoch = int(time.time()) // 60
        knock = create_knock(TEST_BITS, epoch=epoch)

        # Tamper timestamp to be >30s ago
        import struct
        old_ts = int((time.time() - 60) * 1000)  # 60s ago
        tampered = bytearray(knock)
        tampered[7:15] = struct.pack(">Q", old_ts)
        # Tag is now invalid because it covers the old timestamp
        valid, reason = verify_knock(bytes(tampered), TEST_BITS, epoch=epoch)
        self.assertFalse(valid)


class TestReplayRejected(unittest.TestCase):
    """Test that the Gatekeeper rejects replayed knocks."""

    def test_replay(self):
        gk = UDPGatekeeper(
            secret_bits=TEST_BITS,
            listen_port=0,  # not actually binding
            forward_port=0,
        )
        knock = create_knock(TEST_BITS)
        addr = ("192.168.1.100", 5000)

        # First knock: accepted
        action1, fwd1 = gk.handle_packet(knock, addr)
        self.assertEqual(action1, "knock_accepted")
        self.assertFalse(fwd1)

        # Remove from allowlist to force re-evaluation as knock
        gk._allowed.clear()

        # Same knock again: replay rejected
        action2, fwd2 = gk.handle_packet(knock, addr)
        self.assertEqual(action2, "knock_rejected:replay")
        self.assertFalse(fwd2)


class TestAllowlistExpiry(unittest.TestCase):
    """Test that the allowlist entry expires after TTL."""

    def test_expiry(self):
        gk = UDPGatekeeper(
            secret_bits=TEST_BITS,
            listen_port=0,
            forward_port=0,
            ttl_s=0.1,  # 100ms TTL for fast test
        )
        addr = ("192.168.1.100", 5000)

        # Add to allowlist via knock
        knock = create_knock(TEST_BITS)
        action, _ = gk.handle_packet(knock, addr)
        self.assertEqual(action, "knock_accepted")
        self.assertTrue(gk.is_allowed(addr))

        # Wait for expiry
        time.sleep(0.2)

        # Should no longer be allowed
        self.assertFalse(gk.is_allowed(addr))


class TestKnockKeyEpochRotation(unittest.TestCase):
    """Test that knock keys change with epoch."""

    def test_different_epochs(self):
        key_0 = derive_knock_key(TEST_BITS, epoch=0)
        key_1 = derive_knock_key(TEST_BITS, epoch=1)
        self.assertNotEqual(key_0, key_1, "Knock keys must differ across epochs")

    def test_wrong_bits_rejected(self):
        epoch = int(time.time()) // 60
        knock = create_knock(TEST_BITS, epoch=epoch)

        wrong_bits = [0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0]
        valid, reason = verify_knock(knock, wrong_bits, epoch=epoch)
        self.assertFalse(valid, "Knock from different field must be rejected")


class TestGatekeeperForwarding(unittest.TestCase):
    """Test that allowed IPs get their packets forwarded."""

    def test_forward_after_knock(self):
        gk = UDPGatekeeper(
            secret_bits=TEST_BITS,
            listen_port=0,
            forward_port=0,
        )
        addr = ("192.168.1.100", 5000)

        # First: knock to get on allowlist
        knock = create_knock(TEST_BITS)
        gk.handle_packet(knock, addr)

        # Now: regular data should be forwarded
        data = b"some protocol data"
        action, should_forward = gk.handle_packet(data, addr)
        self.assertEqual(action, "forwarded")
        self.assertTrue(should_forward)

    def test_unknown_ip_dropped(self):
        gk = UDPGatekeeper(
            secret_bits=TEST_BITS,
            listen_port=0,
            forward_port=0,
        )
        addr = ("10.0.0.1", 9999)
        data = b"some random data that isnt a knock"
        action, should_forward = gk.handle_packet(data, addr)
        self.assertEqual(action, "dropped")
        self.assertFalse(should_forward)

class TestKnockRateLimit(unittest.TestCase):
    """Test per-IP rate limiting fires before crypto verification."""

    def test_burst_then_limited(self):
        gk = UDPGatekeeper(
            secret_bits=TEST_BITS,
            listen_port=0,
            forward_port=0,
            knock_burst=2,   # only 2 knocks allowed in burst
            knock_rate=0.0,  # no refill (for deterministic test)
        )
        addr = ("10.0.0.50", 4000)

        # First two knocks: should be accepted (burst capacity = 2)
        k1 = create_knock(TEST_BITS)
        a1, _ = gk.handle_packet(k1, addr)
        self.assertEqual(a1, "knock_accepted")

        # Clear allowlist so second knock is evaluated as a knock, not forwarded
        gk._allowed.clear()

        k2 = create_knock(TEST_BITS)
        a2, _ = gk.handle_packet(k2, addr)
        self.assertEqual(a2, "knock_accepted")

        gk._allowed.clear()

        # Third knock: rate limited — no crypto verification happens
        k3 = create_knock(TEST_BITS)
        a3, _ = gk.handle_packet(k3, addr)
        self.assertEqual(a3, "knock_rejected:rate_limited")
        self.assertEqual(gk.stats["knocks_rate_limited"], 1)

    def test_different_ips_independent(self):
        """Rate limit is per-IP — different IPs have their own buckets."""
        gk = UDPGatekeeper(
            secret_bits=TEST_BITS,
            listen_port=0,
            forward_port=0,
            knock_burst=1,
            knock_rate=0.0,
        )

        # IP A uses its one token
        addr_a = ("10.0.0.1", 4000)
        k1 = create_knock(TEST_BITS)
        a1, _ = gk.handle_packet(k1, addr_a)
        self.assertEqual(a1, "knock_accepted")

        # IP B still has its own full bucket
        addr_b = ("10.0.0.2", 4000)
        k2 = create_knock(TEST_BITS)
        a2, _ = gk.handle_packet(k2, addr_b)
        self.assertEqual(a2, "knock_accepted")


if __name__ == "__main__":
    unittest.main()
