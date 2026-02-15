# IDRE Clean Threat Model (v1.2+)

This repo is a **research prototype**. This document is here to prevent accidental overclaims.

## Assets We Protect

- **Payload confidentiality**: only peers with the same private physics (field state/config) can decrypt.
- **Integrity**: message/header tampering is detected (MAC over AAD + ciphertext).
- **Replay resistance**: captured packets should not be accepted again (within the defined policy).

## Adversary Capabilities

- Full network observer (can record all traffic).
- Active MITM: can drop, delay, replay, reorder, and mutate packets/headers.
- Can run their own nodes with arbitrary seeds/configs.
- Can attempt resource exhaustion (oversize bodies/payloads, rapid requests).

## Security Assumptions (Non-Negotiable)

- **Private physics is secret**.
  - In practice this means high-entropy secret material exists and is provisioned securely.
  - If an attacker learns your physics, confidentiality is lost (symmetric-key reality).
- **Clocks are "trusted enough"** when using timestamp enforcement.
  - If clocks are wrong, freshness decisions will reject valid traffic or accept stale traffic.

## Non-Goals

- Traffic analysis resistance is not provided by the core IDRE wire format: metadata (`src/dst/...`) is visible.
  - If you need a global passive observer story, you must add a separate metadata layer (fixed-size constant-rate cells)
    and an anonymity network (Tor/I2P). See `scripts/idre_gateway.py` and `README.md`.
- Public-key infrastructure replacement: IDRE is not a CA system.
- Formal proofs / standards compliance: not yet.
- Post-compromise security / forward secrecy: not claimed.

## What Protects What (In This Repo)

- **Handshake (VERIFY_REQ)**: proves "same field" and establishes a session.
  - v1.2+ adds a **one-time challenge** to prevent VERIFY_REQ replay / session fixation after restart.
- **DATA plane**:
  - `created_at_ms` / `expires_at_ms` are authenticated (in AAD) and enforced for freshness.
  - Replay window is checked after authentication.
- **Offline**:
  - `IDRE-OFFLINE/1` sealed letter is sessionless, time-bounded, and integrity-protected.
  - IDRE-Silence is transport only; it does not add security.
- **Vocab/token payloads (application layer)**:
  - Tokenization is deterministic and authenticated implicitly (it sits inside the encrypted plaintext bytes).
  - A positional vocab mismatch is detected via `vocab_id` and rejected (`wrong_vocab`).
  - Strict mode (`--no-vocab-allow-literals`) removes the out-of-vocab fallback path by policy.

## Known Hard Problems (Roadmap Items)

- Auditing the IDRE primitive as a cipher (cryptanalysis, reduction arguments, side-channels).
- Key provisioning and rotation for "private physics".
- DoS hardening (rate limiting, admission control).
- Forward secrecy (requires additional mechanism; not solved by timestamps).
- Side channels and operational leakage (logs, timing, resource usage).
