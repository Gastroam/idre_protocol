# IDRE Clean: Goal vs Current State

This document is intentionally blunt. It is here to keep reviewers aligned on what this repo *is* and *is not*.

## Goal

- Provide a minimal, reproducible reference implementation of **IDRE/Hive v1.2** primitives + wire framing.
- Provide a black-box adversary harness for regression testing.
- Provide an **offline transport** (IDRE-Silence) that can carry already-secured IDRE bytes through audio.
- Provide an optional **vocab/token codec** to deterministically compress text into token indices (no LLM dependency).

## Current State (What Works)

- **Field-bound verification handshake** (`VERIFY_REQ`): proves peers share the same field.
- **Handshake anti-replay**: one-time challenges prevent VERIFY_REQ replay / session fixation after restart.
- **Per-message integrity**: `HMAC-SHA256(mac_key, aad || ct)` with AAD binding header metadata.
- **Freshness control**: `created_at_ms` / `expires_at_ms` in authenticated AAD with policy enforcement.
- **Replay rejection**: per-session nonce window; replay checked *after* authentication.
- **Noise-tolerant payload framing**: bytes appended after `[ct][tag]` are ignored by design.
- **Vocab/token payloads** (optional): deterministic text encoding with vocab mismatch detection (`wrong_vocab`).
- **Offline sealed letter** (`IDRE-OFFLINE/1`): sessionless, time-bounded, MAC'd envelope carried via audio.
- **IDRE-Silence transport**: bytes <-> audio with CRC32 framing and optional bit repetition FEC (prefix-checked in tooling).

## Known Limitations / Gaps

- **Not audited / not standardized crypto**: this is a research prototype until independently reviewed.
- **Key distribution is out of scope**: security depends on the secrecy of the shared field (seed/weights/config).
- **No forward secrecy claim**: compromise of the field state compromises past/future traffic in this model.
- **Core metadata is plaintext**: `src/dst/session_id/...` are visible on the wire.
  - If you need traffic-analysis resistance, use the optional gateway layer (`scripts/idre_gateway.py`) with fixed-size
    constant-rate cells and run it through Tor/I2P tunnels. This is a separate layer, not "free" from IDRE itself.
- **DoS surface exists**: like any network protocol, endpoints can be resource-targeted without rate limiting.
- **IDRE-Silence is not a hostile-channel modem** (yet): robustness is good under resampling/filters/gain,
  but timing jitter and dropouts can break decode without stronger synchronization/coding.
- **Offline decode performance**: long WAVs can take significant CPU time to decode (pure Python + numpy).
  - This is acceptable for lab/offline workflows; optimizing decode is a future task.

## Recent Security Fixes

- `VERIFY_REQ` now authenticates `session_id` and `ephemeral_salt` (prevents salt/header tamper DoS).
- Replay window update moved to happen only after authentication (prevents window-filling attacks).
- Offline sealed letter payload framing uses a u32 ciphertext-length prefix (prevents truncation/ambiguity).
