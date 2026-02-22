# IDRE Clean: Goal vs Current State

This document is intentionally blunt. It is here to keep reviewers aligned on what this repo *is* and *is not*.

## Goal

- Provide a minimal, reproducible reference implementation of **IDRE/Hive v1.2** primitives + wire framing.
- Provide a black-box adversary harness for regression testing.
- Provide an optional **vocab/token codec** to deterministically compress text into token indices (no LLM dependency).

## Current State (What Works)

- **Field-bound verification handshake** (`VERIFY_REQ`): proves peers share the same field.
- **Handshake anti-replay**: one-time challenges prevent VERIFY_REQ replay / session fixation after restart.
- **Per-message integrity**: `HMAC-SHA256(mac_key, aad || ct)` with AAD binding header metadata.
- **Freshness control**: `created_at_ms` / `expires_at_ms` in authenticated AAD with policy enforcement.
- **Replay rejection**: per-session nonce window; replay checked *after* authentication.
- **Noise-tolerant payload framing**: bytes appended after `[ct][tag]` are ignored by design.
- **Vocab/token payloads** (optional): deterministic text encoding with vocab mismatch detection (`wrong_vocab`).
- **Offline sealed letter** (`IDRE-OFFLINE/1`): sessionless, time-bounded, MAC'd envelope.
- **Neural Payload Compression**: Session-bound learning codec (`NeuralCodec`) for bandwidth efficiency.
- **Weight Hiding**: Secret `pepper` prevents gradient descent seed recovery.
- **Anti-Rollback**: Hash chaining (`Epoch Anchor`) prevents intra-session replay/forking.
- **Ghost Topology**: Deterministic vector-space folding via orthonormal rotation matrix.
- **Dark Mode Gatekeeper (SPA)**: UDP proxy with Single Packet Authorization — drops all traffic by default, validates cryptographic knocks, per-IP rate limiting before crypto.
- **Encrypted Headers + Rotating Route Tags**: Header encryption hides `src/dst/session_id` from observers; 16-byte route tags rotate every epoch for unlinkable routing.
- **Ouroboros Ratchet**: Consensus-triggered key rotation for forward secrecy tied to external finality events.
- **55 passing tests** (35 core + 10 dark mode + 10 encrypted headers).

## Known Limitations / Gaps

- **Not audited / not standardized crypto**: this is a research prototype until independently reviewed.
- **Key distribution is out of scope**: security depends on the secrecy of the Field Provisioning Bundle (seed/topology/pepper/vocabulary).
- **Forward secrecy**: limited to Ouroboros Ratchet (requires external consensus events). No ephemeral DH.
- **Side-channel analysis**: excluded from adversary model. Implementation uses Python (not constant-time).
- **Transport layer**: IDRE-Silence (audio transport) is implemented but excluded from this release; planned for future publication.
- **Float determinism edge cases**: threshold binarization provides margin but deployment-specific calibration is recommended for cross-architecture use.

## Recent Security Additions (v2.4)

- **Dark Mode Gatekeeper**: SPA knock authentication, per-IP token-bucket rate limiting (before crypto), allowlist with TTL.
- **Encrypted Headers**: full header encryption with XOR stream cipher, rotating route tags.
- **Empirical entropy analysis**: 229-bit min-entropy (post-pepper) validated across 100 seeds.
- `VERIFY_REQ` now authenticates `session_id` and `ephemeral_salt` (prevents salt/header tamper DoS).
- Replay window update moved to happen only after authentication (prevents window-filling attacks).
- Offline sealed letter payload framing uses a u32 ciphertext-length prefix (prevents truncation/ambiguity).
