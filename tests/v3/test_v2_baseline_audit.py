"""Reproducible audit baseline observations for IDRE v2 (commit 90daabc).

These tests document the *existing v2 behavior* observed in the audit:
- Genuine neuron plasticity updates change field fingerprints and break fresh
  field-dependent verification and optional encrypted headers.
- Established ratcheted DATA sessions (and adaptive OP_RECALL packets) remain
  decodable after sender-only field drift because `encrypt_bytes`/`decrypt_bytes`
  substitute ratchet-derived bits for the field fingerprint values.

Passing these tests confirms baseline reproduction, NOT v3 security.
"""

from __future__ import annotations

from core.neural_codec import OP_RECALL
from tests.v3.conftest import (
    deliver_exact,
    drift_until_effective_fingerprints_differ,
    fresh_verify,
)


def test_v2_field_drift_leaves_established_data_usable(make_learning_pair):
    a, b = make_learning_pair()

    # 1. Initial established DATA succeeds with exact vocabulary-decoded text.
    res0, text0 = deliver_exact(a, b, "red blue")
    assert res0 == {"status": "delivered"}
    assert text0 == "red blue"

    # 2. Drift only sender's learned field until fingerprints diverge.
    steps, dist, total_bits = drift_until_effective_fingerprints_differ(
        a, b, context=b"learning-audit-context"
    )
    assert steps > 0
    assert dist > 0
    assert total_bits == 288

    # 3. Fresh field-dependent handshake rejects the diverged field.
    assert fresh_verify(a, b) is False

    # 4. Existing ratcheted DATA session still delivers exact text.
    res1, text1 = deliver_exact(a, b, "green red")
    assert res1 == {"status": "delivered"}
    assert text1 == "green red"

    # 5. Same finalized-block ratchet event at both nodes changes ratchet_key,
    #    yet divergent-field DATA still delivers exact text.
    old_ratchet_a = a.sessions["B"].ratchet_key
    old_ratchet_b = b.sessions["A"].ratchet_key
    block_hash = "0x" + "ab" * 32
    a.ingest_finalized_block(block_hash)
    b.ingest_finalized_block(block_hash)
    assert a.sessions["B"].ratchet_key != old_ratchet_a
    assert b.sessions["A"].ratchet_key != old_ratchet_b

    res2, text2 = deliver_exact(a, b, "blue green")
    assert res2 == {"status": "delivered"}
    assert text2 == "blue green"

    # 6. Optional encrypted headers consult the field fingerprint and reject.
    res_hdr, text_hdr = deliver_exact(a, b, "red green", encrypt_headers=True)
    assert res_hdr == {"status": "reject", "reason": "invalid_route_tag"}
    assert text_hdr is None


def test_v2_adaptive_recall_survives_field_drift(make_learning_pair):
    a, b = make_learning_pair()

    # Populate the session dictionary: 3 observations trigger OP_PROPOSE.
    for _ in range(3):
        res, text = deliver_exact(a, b, "red blue")
        assert res == {"status": "delivered"}
        assert text == "red blue"

    # Reverse message carries piggybacked OP_ACK so A promotes the entry.
    res_ack, text_ack = deliver_exact(b, a, "green red")
    assert res_ack == {"status": "delivered"}
    assert text_ack == "green red"

    # Drift only sender A's learned field until fingerprints differ.
    steps, dist, total_bits = drift_until_effective_fingerprints_differ(
        a, b, context=b"recall-audit-context"
    )
    assert steps > 0
    assert dist > 0
    assert total_bits == 288

    # Spy on A's codec encoder to verify the next message actually emits OP_RECALL.
    codec_a = a.sessions["B"].codec
    orig_encode = codec_a.encode
    emitted_streams: list[bytes] = []

    def _spy_encode(plaintext: bytes, injected_packets=None) -> bytes:
        stream = orig_encode(plaintext, injected_packets=injected_packets)
        emitted_streams.append(stream)
        return stream

    codec_a.encode = _spy_encode
    try:
        res_recall, text_recall = deliver_exact(a, b, "red blue")
    finally:
        codec_a.encode = orig_encode

    assert len(emitted_streams) == 1
    recall_stream = emitted_streams[0]
    assert len(recall_stream) == 5
    assert recall_stream[0] == OP_RECALL

    assert res_recall == {"status": "delivered"}
    assert text_recall == "red blue"
