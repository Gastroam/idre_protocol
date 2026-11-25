# IDRE v3 Comparative Evaluation & Claims Ledger (Task 12)

**Measured Commit:** `4c1f98ab575b624871d9a68dcd39cbdf87c55c7f`  
**Platform / Runtime:** `Linux-7.0.0-43-generic-x86_64-with-glibc2.39`, Python `3.12.3`, NumPy `2.4.4`, cryptography `41.0.7`  
**Raw Artifact:** [results_matrix.json](../../benchmarks/v3/results_matrix.json) (`python -m benchmarks.v3.run_matrix`)  
**Workload:** 300 held-out strict-vocabulary messages (`seed=20261125`, ~60% repeated command phrases, ~40% random 4–9 token sequences).

## 1. Matched-Baseline Comparison (Equal Provisioning, Vocab, Framing, AEAD)

| Variant | Total Wire Bytes | Mean B/Msg | Canonical State Size | Accepted Round-Trip (median / p95 / p99 µs) | Field-Drift Reject (median / p95 µs) |
| --- | ---: | ---: | ---: | --- | --- |
| `psk_static` (no evolving state) | 40,086 | 133.62 | 40 B | 189.55 / 342.41 / 489.21 | n/a |
| `hash_state_machine` (32B SHA-256 chain) | 40,086 | 133.62 | 72 B | 293.99 / 438.61 / 558.54 | n/a |
| `idre_v3_strict` (Q16.16 neural field, dict OFF) | 40,086 | 133.62 | 1,370 B | 642.90 / 860.95 / 991.47 | 180.15 / 325.33 |
| `idre_v3_adaptive` (Q16.16 neural field, dict ON) | **32,148** (-19.8%) | **107.16** | 1,767 B | 655.23 / 929.74 / 1,109.35 | 175.47 / 216.72 |

## 2. Negative Control & Isolated Divergence Controls

| Control Experiment | Observed Result | Interpretation |
| --- | --- | --- |
| Full deterministic clone (identical state + observed traffic, 50 msgs) | `1.0` (100% tracking) | **Expected negative control:** deterministic learning does not defeat a complete state clone. |
| Field-only divergence | `field_or_mac_mismatch` | G1 wire fidelity holds even when chain, epoch, seq, and vocab match. |
| Chain-only divergence | `field_or_mac_mismatch` | Chain secret independently binds protection. |
| Epoch-only divergence | `epoch_mismatch` | Epoch label strictly enforced. |
| Vocab-only divergence | `vocab_profile_digest_mismatch` | Trusted provisioning digest rejects mismatched vocabularies fail-closed. |

## 3. Gate Status Summary (G1–G4)

- **G1 (Implementation Fidelity):** **PASS** — ordinary DATA, adaptive `OP_RECALL_V3`, encrypted headers, and post-epoch DATA all reject field-only drift and recover on exact state restoration; legacy v2 bypass routes fail closed.
- **G2 (Deterministic & Transactional Reliability):** **PASS** — 10,000-step fixed-point Q16.16 KAT vectors pass byte-for-byte; MAC-valid invalid payloads preserve state; stop-and-wait retries, crossed sends, and SQLite crash-injection schedules obey the contract.
- **G3 (Independent Security Analysis):** **OPEN** — candidate HKDF-SHA-256 + ChaCha20-Poly1305 schedule is specified in `docs/specs/idre-v3-key-schedule.md` but awaits independent cryptographic review; no adversarial key-commitment proof is claimed.
- **G4 (Neural Value vs. Simpler Baselines):** **NO NEURAL ADVANTAGE ESTABLISHED UNDER M1** — relative to `hash_state_machine`, the 64-dim Q16.16 neural field adds ~1.3 KiB per direction and ~2.2× round-trip CPU overhead without demonstrating an independent wire-size or security advantage. The observed 19.8% wire-byte reduction comes from the orthogonal bounded adaptive dictionary (`core/codec_v3.py`). Unless Task 11 establishes a distinct inner-pointer property, the production profile should treat the neural field as an experimental stateful construction or simplify to the keyed hash state machine.

## 4. Claims Ledger

| Statement | Classification |
| --- | --- |
| Audited v2 (`90daabc`) ratcheted DATA and `OP_RECALL` survive sender-only field drift (22 / 19 updates) | **Observed** (`tests/v3/test_v2_baseline_audit.py`) |
| IDRE v3 rejects field-only drift across DATA, `OP_RECALL_V3`, encrypted headers, and post-epoch DATA | **Observed** (`tests/v3/`) |
| Q16.16 fixed-point field transitions are integer-exact and reproducible across 10,000 steps | **Observed** (`tests/v3/vectors/field_state.json`) |
| Adaptive dictionary reduces wire bytes by 19.8% on the held-out 60%-repeat workload | **Observed** (`benchmarks/v3/results_matrix.json`) |
| Full deterministic clone stays 100% aligned with wire traffic | **Observed** (expected negative control) |
| ChaCha20-Poly1305 + HKDF-SHA-256 provides outsider confidentiality/integrity under 32B CSPRNG provisioning | **Proposed** (pending independent G3 review) |
| Neural field adds independent secret entropy beyond provisioning roots | **Unsupported** (explicitly disclaimed) |
| Software weights are non-exportable or prevent full-clone tracking | **Unsupported** (explicitly disclaimed) |
| Absence of public keys alone proves quantum security | **Unsupported** (explicitly disclaimed) |
