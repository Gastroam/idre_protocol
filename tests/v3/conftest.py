from __future__ import annotations

import json
import logging
import secrets
from pathlib import Path
from typing import Callable, Optional, Tuple

import pytest

from core.vocab_codec import load_vocab_registry
from hive.node import FieldBoundNode

AUDIT_PEPPER = "synthetic-learning-audit-private-pepper"
AUDIT_VOCAB_TOKENS = ["red", "blue", "green", " "]


def hamming_distance(bits_a: list[int], bits_b: list[int]) -> int:
    assert len(bits_a) == len(bits_b)
    return sum(int(x != y) for x, y in zip(bits_a, bits_b))


def drift_until_effective_fingerprints_differ(
    sender: FieldBoundNode,
    receiver: FieldBoundNode,
    *,
    context: bytes = b"learning-audit-context",
    max_steps: int = 200,
) -> Tuple[int, int, int]:
    """Evolve only `sender`'s learned field until effective fingerprints differ."""
    recv_bits = receiver.fingerprint_bits(mutate=False, context_data=context)
    for step in range(1, max_steps + 1):
        sender._evolve_lattice(sender.seed)
        send_bits = sender.fingerprint_bits(mutate=False, context_data=context)
        dist = hamming_distance(send_bits, recv_bits)
        if dist > 0:
            return step, dist, len(recv_bits)
    raise AssertionError(f"Fingerprints did not diverge within {max_steps} updates")


def fresh_verify(initiator: FieldBoundNode, responder: FieldBoundNode) -> bool:
    """Attempt a fresh field-dependent mutual challenge verification."""
    challenge = responder.issue_challenge(initiator.node_id)
    session_id = f"fresh-{secrets.token_hex(6)}"
    ephemeral_salt = secrets.randbits(64)
    req = initiator.create_verify_req(
        session_id=session_id,
        ephemeral_salt=ephemeral_salt,
        challenge=challenge.challenge,
    )
    return bool(responder.process_verify_req(req, peer_id=initiator.node_id))


def deliver_exact(
    sender: FieldBoundNode,
    receiver: FieldBoundNode,
    text: str,
    *,
    encrypt_headers: bool = False,
) -> Tuple[dict, Optional[str]]:
    """Send `text` over the established session and capture the exact delivered string."""
    captured: list[str] = []
    prefix = f"[DELIVERED to {receiver.node_id} from {sender.node_id}] "

    class _DeliveryCapture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            msg = record.getMessage()
            if msg.startswith(prefix):
                captured.append(msg[len(prefix) :])

    node_logger = logging.getLogger("hive.node")
    handler = _DeliveryCapture()
    node_logger.addHandler(handler)
    try:
        pkt = sender.send(receiver.node_id, text, encrypt_headers=encrypt_headers)
        assert pkt, "sender.send() returned an empty packet"
        res = receiver.receive(pkt, prev_hop_id=sender.node_id)
    finally:
        node_logger.removeHandler(handler)

    delivered = captured[-1] if captured else None
    return res, delivered


@pytest.fixture
def make_learning_pair(tmp_path: Path) -> Callable[..., Tuple[FieldBoundNode, FieldBoundNode]]:
    """Create a pair of local v2 lattice-learning nodes with a real mutual handshake.

    Matches the pinned audit baseline (commit 90daabc):
    - Fixed synthetic private vocabulary (`red`, `blue`, `green`, space)
    - Strict vocabulary mode with literal fallback disabled
    - Mandatory synthetic pepper
    - Lattice backend, plasticity enabled, freeze_field disabled, non-anchor learning
    - Real mutual challenge-response handshake (no `force_session`)
    """

    def _factory(
        *,
        anchor_seeds: Tuple[int, ...] = (),
        pepper: str = AUDIT_PEPPER,
        seed: int = 7245,
    ) -> Tuple[FieldBoundNode, FieldBoundNode]:
        vocab_path = tmp_path / f"audit_vocab_{secrets.token_hex(4)}.json"
        vocab_path.write_text(json.dumps(AUDIT_VOCAB_TOKENS), encoding="utf-8")
        registry, vocab = load_vocab_registry([str(vocab_path)])

        common = dict(
            seed=seed,
            anchor_seeds=anchor_seeds,
            anchor_weight=80.0,
            n_angles=72,
            scan_resolution=50,
            threshold=0.5,
            planes=4,
            tau_frac=0.55,
            print_deliveries=True,
            print_events=False,
            freeze_field=False,
            backend="lattice",
            content_codec="vocab",
            vocab=vocab,
            vocab_registry=registry,
            vocab_allow_literals=False,
            plasticity=True,
            pepper=pepper,
        )
        node_a = FieldBoundNode(node_id="A", **common)
        node_b = FieldBoundNode(node_id="B", **common)

        # Real mutual challenge-response handshake (no forced session).
        session_id = f"audit-sess-{secrets.token_hex(6)}"
        ephemeral_salt = secrets.randbits(64)

        ch_b = node_b.issue_challenge("A")
        req_ab = node_a.create_verify_req(session_id, ephemeral_salt, ch_b.challenge)
        assert node_b.process_verify_req(req_ab, peer_id="A") is True

        ch_a = node_a.issue_challenge("B")
        req_ba = node_b.create_verify_req(session_id, ephemeral_salt, ch_a.challenge)
        assert node_a.process_verify_req(req_ba, peer_id="B") is True

        return node_a, node_b

    return _factory
