"""Task 12: Matched-Baseline Evaluation Matrix and Negative Controls for IDRE v3.

Compares four equally provisioned variants on the exact same strict private
vocabulary, 54-byte framing, ChaCha20-Poly1305 AEAD, 32-byte secret budget,
and held-out message workload:
  1. `psk_static`         - Conventional PSK AEAD (no evolving state)
  2. `hash_state_machine` - Keyed 32-byte SHA-256 state machine (non-neural)
  3. `idre_v3_strict`     - IDRE v3 Q16.16 neural field (adaptive dict OFF)
  4. `idre_v3_adaptive`   - IDRE v3 Q16.16 neural field (adaptive dict ON)

Also executes:
  - Full deterministic clone negative control (expected 100% tracking)
  - Isolated divergence controls (field-only, chain-only, vocab-only, epoch-only)
"""

from __future__ import annotations

import hashlib
import json
import platform
import random
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, List, Tuple

import cryptography
import numpy as np

from core.codec_v3 import pack_strict_stream_v3, unpack_strict_stream_v3
from core.field_state_v3 import AcceptedEventV3, FieldStateError, FieldViewV3, advance_field
from core.profile_v3 import (
    MSG_TYPE_DATA,
    ProfileV3,
    ProfileValidationError,
    ProvisioningBundleV3,
    TranscriptV3,
    canonical_profile,
    compute_vocab_digest_v3,
)
from core.session_v3 import encode_direction_state
from core.vocab_codec import load_vocab
from core.vocab_v3 import decode_strict_v3, encode_strict_v3
from hive.crypto_v3 import aead_open, aead_seal, pack_frame_v3, parse_frame_v3
from hive.engine_v3 import (
    EngineError,
    direction_message_context,
    prepare_send,
    validate_ack,
    validate_receive,
)
from hive.key_schedule_v3 import (
    compute_handshake_confirm,
    derive_message_keys,
    establish_confirmed_session,
    initialize_session,
)

BENCH_TOKENS = ["red", "blue", "green", "alpha", "beta", "gamma", "delta", " "]


def build_held_out_workload(n_messages: int = 300, seed: int = 20261125) -> List[str]:
    """Deterministic held-out workload with realistic command repetition (~60% repeated phrases)."""
    rng = random.Random(seed)
    words = [t for t in BENCH_TOKENS if t != " "]
    hot_phrases = [
        "alpha beta gamma delta alpha beta",
        "red blue green red blue green",
        "delta gamma beta alpha delta gamma",
        "green red blue alpha beta",
        "beta alpha delta red green",
    ]
    out: List[str] = []
    for _ in range(n_messages):
        if rng.random() < 0.60:
            out.append(rng.choice(hot_phrases))
        else:
            k = rng.randint(4, 9)
            out.append(" ".join(rng.choice(words) for _ in range(k)))
    return out


def _percentiles_us(samples_ns: List[int]) -> Dict[str, float]:
    s = sorted(samples_ns)
    n = len(s)
    if n == 0:
        return {"median_us": 0.0, "p95_us": 0.0, "p99_us": 0.0}
    return {
        "median_us": round(statistics.median(s) / 1000.0, 2),
        "p95_us": round(s[min(n - 1, int(0.95 * n))] / 1000.0, 2),
        "p99_us": round(s[min(n - 1, int(0.99 * n))] / 1000.0, 2),
    }


def _make_v3_pair(tmp_dir: Path, *, adaptive: bool) -> Tuple[Any, Any, ProfileV3, Any]:
    vp = tmp_dir / f"bench_vocab_{adaptive}.json"
    vp.write_text(json.dumps(BENCH_TOKENS), encoding="utf-8")
    vocab = load_vocab(str(vp))
    profile = ProfileV3(
        bundle_id=b"\xab" * 16,
        expected_vocab_digest=compute_vocab_digest_v3(vocab),
        adaptive_codec_enabled=adaptive,
    )
    net_sec = b"\x11" * 32
    fld_sec = b"\x22" * 32
    ba = ProvisioningBundleV3(profile, net_sec, fld_sec, profile.expected_vocab_digest, "A")
    bb = ProvisioningBundleV3(profile, net_sec, fld_sec, profile.expected_vocab_digest, "B")
    tr = TranscriptV3(
        profile_bytes=canonical_profile(profile),
        session_id=b"\x33" * 16,
        initiator_id="A",
        responder_id="B",
        initiator_nonce=b"\x44" * 32,
        responder_nonce=b"\x55" * 32,
    )
    ca = initialize_session(ba, tr)
    cb = initialize_session(bb, tr)
    sa = establish_confirmed_session(ba, tr, peer_confirm_tag=compute_handshake_confirm(bb, cb))
    sb = establish_confirmed_session(bb, tr, peer_confirm_tag=compute_handshake_confirm(ba, ca))
    return sa, sb, profile, vocab


def run_psk_baseline(workload: List[str], tmp_dir: Path) -> Dict[str, Any]:
    """Conventional PSK ChaCha20-Poly1305 with the exact same strict vocab & 54B framing."""
    sa, _sb, profile, vocab = _make_v3_pair(tmp_dir, adaptive=False)
    static_view = FieldViewV3(profile_digest=b"\x00" * 32, age=0, binding_bytes=b"\x00" * 32)
    static_key = b"\x11" * 32

    lat_ns: List[int] = []
    wire_bytes = 0
    for seq, msg in enumerate(workload):
        ctx = direction_message_context(sa, direction=sa.tx.direction, epoch=1, seq=seq)
        t0 = time.perf_counter_ns()
        vblob = encode_strict_v3(msg, vocab, max_plaintext_bytes=profile.max_plaintext_bytes)
        stream = pack_strict_stream_v3(vblob, max_plaintext_bytes=profile.max_plaintext_bytes)
        keys = derive_message_keys(static_view, static_key, ctx)
        probe = pack_frame_v3(
            msg_type=MSG_TYPE_DATA,
            flags=0,
            direction=sa.tx.direction,
            bundle_id=profile.bundle_id,
            session_id=sa.session_id,
            epoch=1,
            seq=seq,
            body_bytes=b"\x00" * (len(stream) + 16),
        )
        hdr = probe[:54]
        pkt = hdr + aead_seal(keys.body_key, keys.body_nonce, stream, hdr)
        wire_bytes += len(pkt)
        frame = parse_frame_v3(pkt)
        pt_stream = aead_open(keys.body_key, keys.body_nonce, frame.body_bytes, frame.header_bytes)
        dec = decode_strict_v3(
            unpack_strict_stream_v3(pt_stream, max_plaintext_bytes=profile.max_plaintext_bytes),
            vocab,
            max_plaintext_bytes=profile.max_plaintext_bytes,
        )
        t1 = time.perf_counter_ns()
        assert dec == msg
        lat_ns.append(t1 - t0)

    return {
        "variant": "psk_static",
        "messages": len(workload),
        "data_wire_bytes": wire_bytes,
        "ack_wire_bytes": 0,
        "total_wire_bytes": wire_bytes,
        "mean_data_wire_bytes": round(wire_bytes / len(workload), 2),
        "mean_total_wire_bytes": round(wire_bytes / len(workload), 2),
        "state_size_bytes": 32 + 8,  # 32B key + 8B seq
        "accepted_roundtrip": _percentiles_us(lat_ns),
    }


def run_hash_state_baseline(workload: List[str], tmp_dir: Path) -> Dict[str, Any]:
    """Non-neural keyed SHA-256 evolving state machine under matched provisioning & framing."""
    sa, _sb, profile, vocab = _make_v3_pair(tmp_dir, adaptive=False)
    state_a = hashlib.sha256(b"HASH-STATE-INIT|" + b"\x22" * 32).digest()
    state_b = state_a
    chain_key = b"\x11" * 32

    lat_ns: List[int] = []
    wire_bytes = 0
    for seq, msg in enumerate(workload):
        ctx = direction_message_context(sa, direction=sa.tx.direction, epoch=1, seq=seq)
        t0 = time.perf_counter_ns()
        vblob = encode_strict_v3(msg, vocab, max_plaintext_bytes=profile.max_plaintext_bytes)
        stream = pack_strict_stream_v3(vblob, max_plaintext_bytes=profile.max_plaintext_bytes)
        view_a = FieldViewV3(profile_digest=b"\x00" * 32, age=seq, binding_bytes=state_a)
        keys_a = derive_message_keys(view_a, chain_key, ctx)
        probe = pack_frame_v3(
            msg_type=MSG_TYPE_DATA,
            flags=0,
            direction=sa.tx.direction,
            bundle_id=profile.bundle_id,
            session_id=sa.session_id,
            epoch=1,
            seq=seq,
            body_bytes=b"\x00" * (len(stream) + 16),
        )
        hdr = probe[:54]
        pkt = hdr + aead_seal(keys_a.body_key, keys_a.body_nonce, stream, hdr)
        wire_bytes += len(pkt)

        view_b = FieldViewV3(profile_digest=b"\x00" * 32, age=seq, binding_bytes=state_b)
        keys_b = derive_message_keys(view_b, chain_key, ctx)
        frame = parse_frame_v3(pkt)
        pt_stream = aead_open(keys_b.body_key, keys_b.body_nonce, frame.body_bytes, frame.header_bytes)
        dec = decode_strict_v3(
            unpack_strict_stream_v3(pt_stream, max_plaintext_bytes=profile.max_plaintext_bytes),
            vocab,
            max_plaintext_bytes=profile.max_plaintext_bytes,
        )
        state_a = hashlib.sha256(state_a + seq.to_bytes(8, "big")).digest()
        state_b = hashlib.sha256(state_b + seq.to_bytes(8, "big")).digest()
        t1 = time.perf_counter_ns()
        assert dec == msg
        lat_ns.append(t1 - t0)

    return {
        "variant": "hash_state_machine",
        "messages": len(workload),
        "data_wire_bytes": wire_bytes,
        "ack_wire_bytes": 0,
        "total_wire_bytes": wire_bytes,
        "mean_data_wire_bytes": round(wire_bytes / len(workload), 2),
        "mean_total_wire_bytes": round(wire_bytes / len(workload), 2),
        "state_size_bytes": 32 + 32 + 8,  # 32B state + 32B chain + 8B seq
        "accepted_roundtrip": _percentiles_us(lat_ns),
    }


def run_idre_v3_variant(workload: List[str], tmp_dir: Path, *, adaptive: bool) -> Dict[str, Any]:
    """Full IDRE v3 Q16.16 neural field engine (with or without adaptive dictionary)."""
    sa, sb, profile, vocab = _make_v3_pair(tmp_dir, adaptive=adaptive)
    tx, rx = sa.tx, sb.rx

    lat_ns: List[int] = []
    data_wire_bytes = 0
    ack_wire_bytes = 0
    for seq, msg in enumerate(workload):
        ctx = direction_message_context(sa, direction=tx.direction, epoch=1, seq=seq)
        t0 = time.perf_counter_ns()
        prep = prepare_send(tx, msg, ctx, profile=profile, vocab=vocab)
        data_wire_bytes += len(prep.packet_bytes)
        val = validate_receive(rx, prep.packet_bytes, ctx, profile=profile, vocab=vocab)
        ack_wire_bytes += len(val.ack_packet_bytes)
        tx = validate_ack(prep.pending_state, val.ack_packet_bytes, profile=profile, session_id=sa.session_id)
        rx = val.next_state
        t1 = time.perf_counter_ns()
        assert val.plaintext == msg
        lat_ns.append(t1 - t0)

    # Measure rejection cost under field-only drift
    rej_ns: List[int] = []
    ctx_next = direction_message_context(sa, direction=tx.direction, epoch=1, seq=tx.next_seq)
    prep_next = prepare_send(tx, workload[0], ctx_next, profile=profile, vocab=vocab)
    drifted_rx = replace(rx, field=advance_field(rx.field, AcceptedEventV3("data_accepted", seq=9999, epoch=1)))
    for _ in range(50):
        t0 = time.perf_counter_ns()
        try:
            validate_receive(drifted_rx, prep_next.packet_bytes, ctx_next, profile=profile, vocab=vocab)
            raise AssertionError("drifted_rx should have rejected")
        except EngineError:
            pass
        rej_ns.append(time.perf_counter_ns() - t0)

    total_wire_bytes = data_wire_bytes + ack_wire_bytes
    return {
        "variant": "idre_v3_adaptive" if adaptive else "idre_v3_strict",
        "messages": len(workload),
        "data_wire_bytes": data_wire_bytes,
        "ack_wire_bytes": ack_wire_bytes,
        "total_wire_bytes": total_wire_bytes,
        "mean_data_wire_bytes": round(data_wire_bytes / len(workload), 2),
        "mean_total_wire_bytes": round(total_wire_bytes / len(workload), 2),
        "state_size_bytes": len(encode_direction_state(rx)),
        "accepted_roundtrip": _percentiles_us(lat_ns),
        "rejected_field_drift": _percentiles_us(rej_ns),
    }


def run_negative_and_divergence_controls(tmp_dir: Path, n_messages: int = 50) -> Dict[str, Any]:
    """Run full deterministic clone negative control + isolated divergence controls."""
    workload = build_held_out_workload(n_messages=n_messages)
    sa, sb, profile, vocab = _make_v3_pair(tmp_dir, adaptive=True)

    # Full deterministic clone starts with identical rx state and observes all wire traffic.
    # Expected under stated model: 100% alignment (deterministic learning is NOT clone-proof).
    tx = sa.tx
    rx = sb.rx
    clone_rx = sb.rx
    clone_matches = 0
    for seq, msg in enumerate(workload):
        ctx = direction_message_context(sa, direction=tx.direction, epoch=1, seq=seq)
        prep = prepare_send(tx, msg, ctx, profile=profile, vocab=vocab)
        val_legit = validate_receive(rx, prep.packet_bytes, ctx, profile=profile, vocab=vocab)
        val_clone = validate_receive(clone_rx, prep.packet_bytes, ctx, profile=profile, vocab=vocab)
        assert val_legit.plaintext == msg
        if val_clone.plaintext == msg:
            clone_matches += 1
        tx = validate_ack(prep.pending_state, val_legit.ack_packet_bytes, profile=profile, session_id=sa.session_id)
        rx = val_legit.next_state
        clone_rx = val_clone.next_state

    # Isolated divergence controls (each changes ONLY one component)
    ctx_test = direction_message_context(sa, direction=tx.direction, epoch=1, seq=tx.next_seq)
    prep_test = prepare_send(tx, workload[0], ctx_test, profile=profile, vocab=vocab)

    def _rejects(mutated_rx, *, test_vocab=vocab, test_profile=profile) -> str:
        try:
            validate_receive(mutated_rx, prep_test.packet_bytes, ctx_test, profile=test_profile, vocab=test_vocab)
        except EngineError as exc:
            return exc.reason
        except ProfileValidationError:
            return "vocab_profile_digest_mismatch"
        except FieldStateError:
            return "field_profile_digest_mismatch"
        raise AssertionError("Expected rejection")

    vp_other = tmp_dir / "other_ctrl_vocab.json"
    vp_other.write_text(json.dumps(["zzz", "yyy", " "]), encoding="utf-8")
    other_vocab = load_vocab(str(vp_other))

    controls = {
        "full_clone_tracking_rate": clone_matches / n_messages,
        "field_only_divergence_reason": _rejects(
            replace(rx, field=advance_field(rx.field, AcceptedEventV3("data_accepted", seq=888, epoch=1)))
        ),
        "chain_only_divergence_reason": _rejects(replace(rx, chain_secret=b"\xff" * 32)),
        "epoch_only_divergence_reason": _rejects(replace(rx, epoch=2)),
        "vocab_only_divergence_reason": _rejects(rx, test_vocab=other_vocab, test_profile=profile),
    }
    return controls


def run_full_matrix(n_messages: int = 300) -> Dict[str, Any]:
    workload = build_held_out_workload(n_messages=n_messages)
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        commit = "unknown"

    with tempfile.TemporaryDirectory() as td:
        tmp_dir = Path(td)
        variants = [
            run_psk_baseline(workload, tmp_dir),
            run_hash_state_baseline(workload, tmp_dir),
            run_idre_v3_variant(workload, tmp_dir, adaptive=False),
            run_idre_v3_variant(workload, tmp_dir, adaptive=True),
        ]
        controls = run_negative_and_divergence_controls(tmp_dir, n_messages=50)

    return {
        "commit": commit,
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "numpy": np.__version__,
        "cryptography": cryptography.__version__,
        "workload_messages": n_messages,
        "variants": variants,
        "controls": controls,
    }


if __name__ == "__main__":
    report = run_full_matrix(n_messages=300)
    out_path = Path(__file__).parent / "results_matrix.json"
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
