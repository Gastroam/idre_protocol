# IDRE Threat Model (v2.4)

This repo is a **research prototype**. This document prevents accidental overclaims.

## Scope

IDRE targets **sovereign, pre-provisioned networks** — military enclaves, embassy links, air-gapped meshes — where third-party trust (PKI, CAs) is unacceptable. It is **not** a replacement for TLS, Signal, or WireGuard on the public internet.

## Assets We Protect

- **Payload confidentiality**: only peers with the same Field Provisioning Bundle can decrypt.
- **Integrity**: message/header tampering is detected (MAC over AAD + ciphertext).
- **Replay resistance**: captured packets are not accepted again (nonce window + chain hash).
- **Metadata confidentiality** (optional): encrypted headers and rotating route tags hide `src/dst/session_id` from observers.
- **Service stealth** (optional): Dark Mode Gatekeeper makes ports appear closed to scanners.

## Adversary Capabilities

- Full network observer (can record all traffic).
- Active MITM: can drop, delay, replay, reorder, and mutate packets/headers.
- Can run their own nodes with arbitrary seeds/configs.
- Can attempt resource exhaustion (oversize bodies/payloads, rapid requests).
- Algorithm knowledge: knows the full IDRE specification and source code.
- Model access: possesses base model weights (not the private Field Provisioning Bundle).

## Security Assumptions

- **The Field Provisioning Bundle is secret.**
  - Comprises: seed, topology seed, pepper, vocabulary. All must remain confidential.
  - If an attacker learns the full bundle, confidentiality is lost (symmetric-key reality).
  - Partial compromise (any single component) yields noise, not plaintext (see §4.1 of the paper).
- **Clocks are "trusted enough"** when using timestamp enforcement.
- **Provisioning channel is secure.** The security of out-of-band provisioning is outside IDRE's scope.

## What Protects What

| Layer | Mechanism | Protection |
|:---|:---|:---|
| Handshake (`VERIFY_REQ`) | One-time challenge + field proof | Same-field authentication, session fixation prevention |
| Data plane | HMAC-SHA256(mac_key, aad ∥ ct) | Integrity + authenticity |
| Freshness | `created_at_ms` / `expires_at_ms` in AAD | Stale packet rejection |
| Anti-replay | Per-session nonce window (checked after auth) | Replay rejection |
| Anti-rollback | Epoch Anchor chain hash | Intra-session tamper/fork detection |
| Weight Hiding | `HMAC(pepper, raw_bits)` | Gradient-descent resistance |
| Encrypted Headers | XOR stream cipher on header dict | Metadata confidentiality |
| Route Tags | `SHA256("ROUTE/" ∥ B ∥ epoch)[:16]` | Unlinkable cross-epoch routing |
| Dark Mode Gatekeeper | SPA knock + per-IP rate limiting | Service stealth + DoS mitigation |
| Ouroboros Ratchet | Consensus-triggered key rotation | Forward secrecy (per epoch) |
| Ghost Topology | Orthonormal fold matrix | Independent geometric obfuscation |
| Neural Codec | Session-bound Hebbian compression | Traffic shape obfuscation |
| Vocab binding | `vocab_id = SHA256(tokens)` | Network domain separation |

## Excluded from Adversary Model

- **Side-channel attacks**: timing, power, electromagnetic analysis. Implementation is in Python (not constant-time). Protocol-level analysis only.
- **Quantum adversary** (post-Grover): symmetric components (HMAC-SHA256) are affected by Grover's quadratic speedup. With ≥256-bit equivalent entropy in the bundle, this remains infeasible.

## Known Hard Problems (Future Work)

- Independent cryptanalysis of the IDRE stream cipher (Permute→XOR).
- Standard-model proof (currently ROM only).
- Formal verification (Tamarin/ProVerif).
- Key provisioning UX and rotation workflows.
- Side-channel hardening for non-Python implementations.
- Transport layer security (IDRE-Silence robustness).
