# IDRE v3 Mode & Plaintext-Release Coverage Inventory (Task 10)

Every plaintext-release and recovery path from the audited v2 codebase is explicitly classified below. No convenience path may bypass v3 field-dependent AEAD validation.

| Path / Mode | v3 Status | Enforcement |
| --- | --- | --- |
| Ordinary DATA (`OP_LITERAL_V3`) | **Enabled** | Single path via `hive.engine_v3.validate_receive`; binds `FieldViewV3` + `chain_secret` |
| Adaptive dictionary DATA (`OP_PROPOSE_V3`, `OP_RECALL_V3`) | **Enabled (profile opt-in)** | Same AEAD path (`validate_receive`); 128-bit directional labels, 512 entries / 128 KiB caps, atomic ACK promotion |
| Encrypted headers + route tags | **Enabled (profile opt-in)** | Derived from the same immutable pre-message `FieldViewV3` snapshot as `body_key` |
| Coordinated finalized-block epochs | **Enabled (profile opt-in)** | Ordered, authority-MAC-verified, idempotent, requires drained `pending_send`; preserves field binding |
| Authenticated checkpoint recovery | **Enabled** | `hive.state_store_v3.StateStoreV3` with HMAC-authenticated rows; backup restore forces fresh session |
| Ratchet-only DATA fallback | **Removed** | `derive_message_keys` has no optional field parameter |
| Legacy v2 automatic fallback | **Disabled (fail-closed)** | Rejected by `validate_profile` and `hive.cli` `--protocol-version v3` |
| Frozen backend / disabled plasticity | **Disabled (fail-closed)** | Rejected by `validate_profile` and `hive.cli` |
| UTF-8 / literal vocabulary escape | **Disabled (fail-closed)** | Strict vocabulary mode enforced in `vocab_v3` and `validate_receive` |
| Seed-only offline envelope opening | **Disabled (fail-closed)** | `open_offline_envelope_v3` raises `seed_only_offline_open_disabled_in_v3` |
| Speculative multiverse healing | **Disabled (fail-closed)** | `fork_multiverse_timeline_v3` raises `multiverse_healing_disabled_in_v3` |
| Unconfirmed forced sessions | **Disabled (fail-closed)** | `force_session_v3` raises `forced_session_disabled_in_v3` |
