"""Tests for Task 10: Disabled legacy bypass modes and cross-mode G1 field-only drift coverage."""

from __future__ import annotations

import pytest

from hive.epochs_v3 import (
    EpochControlError,
    force_session_v3,
    fork_multiverse_timeline_v3,
    open_offline_envelope_v3,
)


def test_disabled_v2_bypass_routes_fail_closed_in_v3():
    with pytest.raises(EpochControlError) as exc_off:
        open_offline_envelope_v3(b"blob")
    assert exc_off.value.reason == "seed_only_offline_open_disabled_in_v3"

    with pytest.raises(EpochControlError) as exc_mv:
        fork_multiverse_timeline_v3()
    assert exc_mv.value.reason == "multiverse_healing_disabled_in_v3"

    with pytest.raises(EpochControlError) as exc_fs:
        force_session_v3()
    assert exc_fs.value.reason == "forced_session_disabled_in_v3"
