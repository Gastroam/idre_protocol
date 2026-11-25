"""Tests for Task 12: Matched-baseline evaluation harness, full-clone negative control, and divergence controls."""

from __future__ import annotations

from benchmarks.v3.run_matrix import run_full_matrix


def test_matched_baseline_matrix_and_negative_controls():
    report = run_full_matrix(n_messages=40)
    by_name = {v["variant"]: v for v in report["variants"]}

    assert set(by_name.keys()) == {
        "psk_static",
        "hash_state_machine",
        "idre_v3_strict",
        "idre_v3_adaptive",
    }

    # Adaptive compression should reduce wire bytes on the repeated-phrase workload
    assert by_name["idre_v3_adaptive"]["total_wire_bytes"] < by_name["idre_v3_strict"]["total_wire_bytes"]

    # Negative control: full deterministic clone MUST track 100% under the stated model
    controls = report["controls"]
    assert controls["full_clone_tracking_rate"] == 1.0

    # Isolated divergence controls all reject cleanly
    assert controls["field_only_divergence_reason"] == "field_or_mac_mismatch"
    assert controls["chain_only_divergence_reason"] == "field_or_mac_mismatch"
    assert controls["epoch_only_divergence_reason"] == "epoch_mismatch"
    assert controls["vocab_only_divergence_reason"] == "vocab_profile_digest_mismatch"
