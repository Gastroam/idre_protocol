# IDRE v3 Baseline Evidence Record (Task 0)

**Status:** Baseline reproduction only. No v3 security property, performance result, or deployment certification is claimed.

## Pinned Baseline & Environment

- **Audited commit:** `90daabcbb5c2610fe89f269f4ea386963881a345` (`Ready-for-testing`)
- **Development worktree:** `/home/aleks/idre-v3/idre_protocol-v3` (branch `v3/baseline`)
- **Platform:** `Linux-7.0.0-43-generic-x86_64-with-glibc2.39`
- **Python:** `3.12.3`
- **NumPy:** `2.4.4`
- **cryptography:** `41.0.7`
- **pytest:** `9.0.3`
- **wheel:** `0.42.0`
- **pip:** `24.0`

## Pre-existing Test Suite & Packaging Findings

1. **Pre-existing pytest suite (before edits):**
   - Command: `python -m pytest tests/ -rs`
   - Result: `60 passed, 1 skipped in 3.66s`
   - Pre-existing skip: `tests/test_silence_transport.py:7` (`could not import 'transports.idre_silence': No module named 'transports'`).

2. **Clean wheel packaging defect (repaired in `pyproject.toml`):**
   - Before repair: building a wheel with `python -m pip wheel --no-build-isolation --no-deps .` omitted `vendor/` (`HAS vendor: False`) and declared no runtime `Requires-Dist` entries, masked by editable installs.
   - Repair: added `vendor`, `vendor.mti_evo`, and `vendor.mti_evo.core` to `[tool.setuptools].packages`, declared `dependencies = ["numpy>=2.0", "cryptography>=41.0"]`, and added `dev = ["pytest>=8.0"]`.
   - Verification: rebuilt wheel, installed into a fresh venv, and imported `hive.node` and `vendor.mti_evo.core.lattice` from `/tmp` (`HAS vendor: True`; `Requires-Dist: cryptography >=41.0`, `numpy >=2.0`).

## Reproduced v2 Dependency Observations

Reproduced offline via `tests/v3/conftest.py` (`make_learning_pair` fixture) and `tests/v3/test_v2_baseline_audit.py`:
- Real mutual challenge-response handshake (no `force_session`)
- Synthetic private vocabulary: `["red", "blue", "green", " "]`
- Strict vocabulary mode (`content_codec="vocab"`, `vocab_allow_literals=False`)
- Mandatory pepper: `synthetic-learning-audit-private-pepper`
- Lattice backend, `plasticity=True`, `freeze_field=False`, `anchor_seeds=()`, `seed=7245`, `planes=4`, `n_angles=72`, `scan_resolution=50`, `threshold=0.5`, `anchor_weight=80.0`, `tau_frac=0.55`

| Audit Case | Observation | Result |
| --- | --- | --- |
| `test_v2_field_drift_leaves_established_data_usable` | Sender-only drift (`context=b"learning-audit-context"`) | `22` updates; `141 / 288` bits differed |
| `test_v2_field_drift_leaves_established_data_usable` | Fresh mutual handshake after drift | Rejected (`False`) |
| `test_v2_field_drift_leaves_established_data_usable` | Existing established DATA session after drift | Delivered exact text (`"green red"`) |
| `test_v2_field_drift_leaves_established_data_usable` | Same finalized-block ratchet event at both nodes | Ratchet rotated; divergent-field DATA still delivered (`"blue green"`) |
| `test_v2_field_drift_leaves_established_data_usable` | Optional encrypted header after drift | Rejected (`invalid_route_tag`) |
| `test_v2_adaptive_recall_survives_field_drift` | Sender-only drift after dictionary promotion (`context=b"recall-audit-context"`) | `19` updates; `125 / 288` bits differed |
| `test_v2_adaptive_recall_survives_field_drift` | Repeated `"red blue"` after drift | Emitted 5-byte `OP_RECALL` (`0x02`); delivered exact text (`"red blue"`) |

## Verification Commands & Outputs

```bash
/home/aleks/idre-v3/.venv-v3/bin/python -m pytest tests/v3/ -v
# 2 passed in 0.15s

/home/aleks/idre-v3/.venv-v3/bin/python -m pytest tests/
# 62 passed, 1 skipped in 3.76s
```
