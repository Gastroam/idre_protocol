# IDRE Clean Roadmap (Future-Proofing)

This roadmap is intentionally pragmatic: what to do next, what to avoid claiming, and why.

## 1) "Open Protocol With Private Physics" (Make It Explicit)

- Treat private physics as **key material**.
- Require high-entropy secrets (do not use small demo seeds for real security).
- Define provisioning, rotation, and compromise response.

## 2) Post-Quantum Reality Check

IDRE (as used here) behaves like a **symmetric** system: an attacker without the physics cannot decrypt.
Quantum computers mainly threaten:

- Public-key crypto (RSA/ECC) via Shor (not used here).
- Symmetric crypto via Grover (quadratic speedup).

Practical implication:
- Ensure the private physics has enough entropy (target >= 256-bit equivalent).
- Keep HMAC-SHA256 and the field-derived MAC key; consider SHA-512/256 variants if desired, but entropy is the bigger issue.

## 3) DDoS and Resource Exhaustion

Field-bound crypto does not stop volumetric DDoS by itself.

Add:
- Per-IP / per-peer rate limits
- Hard caps on body sizes, payload sizes, and concurrent sessions (some are already present)
- Cheap early rejects (wrong `field_profile_id`, bad JSON, missing fields)
- Optional proof-of-work / puzzles only if you need open internet exposure

## 3.5) Global Observer (Metadata Layer)

If you want to cross from LAN demos to the open Internet, treat metadata protection as a separate layer:

- Keep the IDRE node localhost-only
- Put a gateway in front that emits fixed-size constant-rate cells (cover traffic)
- Run that gateway through Tor/I2P tunnels

This repo includes a minimal gateway (`scripts/idre_gateway.py`) and a local smoke test (`attacks/idre_gateway_smoke.py`).

## 4) Compliance / Audit Without Plaintext

Add a tamper-evident log mode:
- Hash-chained event log (append-only JSONL)
- Store only:
  - message metadata (field_profile_id, src/dst, created/expires, nonce hash)
  - verification outcomes (verified/reject reason)
  - envelope hashes (SHA-256 of sealed letter blob)
- Never store plaintext or physics

## 5) Offline "Sealed Letter" Improvements

Current state:
- Works as an encrypted+MAC'd blob carried by IDRE-Silence WAV.
- Can carry UTF-8 bytes or vocab/token payloads (codec blob inside the sealed envelope).

Next hardening:
- Stronger sync/FEC for hostile audio channels (dropouts/jitter)
- Optional chunking for large letters with per-chunk MAC + manifest
- Human-safe UX: explicit "import/decrypt" steps, and clear expiration behavior
- Decode performance improvements for long WAVs (faster preamble search, early-stop heuristics)

## 6) AI/LLM Integration (Use It Correctly)

Good uses:
- Analyze logs and attack-suite outputs
- Suggest new fuzz cases, detect anomaly patterns, generate reports


## 7) Neural Payload Compression (Resonant Dictionary) [DONE]

Leverage the neural mechanics for efficiency:
- **Resonant Dictionary**: Learn frequent patterns during a session.
- **Dynamic Neuron IDs**: Replace recurring text/bytes with short 4-byte IDs.
- **Session-Bound**: Dictionary is ephemeral and encrypted (no static lookup tables to steal).
- **Target**: High-repetition traffic (protocol headers, chat commands, sensor data).
- **Status**: Implemented as `NeuralCodec` / `VocabCodec`. Integrated into `node.py`.
