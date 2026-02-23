import unittest

from core.vocab_codec import Vocab
from hive.node import FieldBoundNode

def _create_dummy_vocab():
    tokens = ["<pad>", "<a>", "<b>", "<c>"]
    t2i = {t: i for i, t in enumerate(tokens)}
    return Vocab(tokens=tokens, token_to_index=t2i, vocab_id=b"DUMMY", lens_by_first_char={})

class TestVerifyReqSecurity(unittest.TestCase):
    def setUp(self):
        seed = 12345
        vocab = _create_dummy_vocab()
        self.node_a = FieldBoundNode(
            pepper="test_pepper",
            node_id="A",
            seed=seed,
            anchor_seeds=(seed,),
            anchor_weight=1.0,
            n_angles=16,
            scan_resolution=16,
            threshold=0.1,
            planes=1,
            tau_frac=0.5,
            print_deliveries=False,
            print_events=False,
            freeze_field=True,
            backend="frozen",
            vocab=vocab,
        )
        self.node_b = FieldBoundNode(
            pepper="test_pepper",
            node_id="B",
            seed=seed,
            anchor_seeds=(seed,),
            anchor_weight=1.0,
            n_angles=16,
            scan_resolution=16,
            threshold=0.1,
            planes=1,
            tau_frac=0.5,
            print_deliveries=False,
            print_events=False,
            freeze_field=True,
            backend="frozen",
            vocab=vocab,
        )

    def _new_verify_req(self):
        rec = self.node_b.issue_challenge("A")
        return self.node_a.create_verify_req(
            session_id="verify-req-security",
            ephemeral_salt=42,
            challenge=str(rec.challenge),
        )

    def test_verify_req_is_single_use(self):
        msg = self._new_verify_req()
        self.assertTrue(self.node_b.process_verify_req(msg, peer_id="A", ttl_s=60.0))
        self.assertFalse(self.node_b.process_verify_req(msg, peer_id="A", ttl_s=60.0))

    def test_verify_req_rejects_if_consume_fails(self):
        msg = self._new_verify_req()
        original_consume = self.node_b._challenges.consume
        self.node_b._challenges.consume = lambda _pid, _ch: False  # type: ignore[assignment]
        try:
            ok = self.node_b.process_verify_req(msg, peer_id="A", ttl_s=60.0)
        finally:
            self.node_b._challenges.consume = original_consume  # type: ignore[assignment]

        self.assertFalse(ok)
        self.assertNotIn("A", self.node_b.timelines)

if __name__ == "__main__":
    unittest.main()
