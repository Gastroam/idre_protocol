# IDRE — Integer-Dependent Receiver Encoding

A field-bound cryptographic protocol for sovereign, pre-provisioned networks.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-62_passing-brightgreen.svg)](#tests)
[![Paper](https://img.shields.io/badge/paper-v2.4-orange.svg)](docs/IDRE-PAPER-v1)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](#quickstart)

## What Is IDRE?

IDRE binds decoding capability to a **non-exportable geometric configuration** (the Field Provisioning Bundle) rather than a stored key. Nodes exchange semantic-free integers that are meaningless without the receiver's field geometry.

**Target environment:** military enclaves, embassy links, air-gapped meshes — anywhere third-party trust (PKI, CAs) is unacceptable and out-of-band provisioning is the norm.

**IDRE is not** a replacement for TLS, Signal, or WireGuard on the public internet.

## Key Properties

| Property | Mechanism |
|:---|:---|
| **Post-quantum by construction** | No asymmetric ops, no keys on the wire |
| **Partial-compromise resilience** | 5-dimensional bundle — any single leak yields noise |
| **Metadata protection** | Encrypted headers + rotating route tags (Dark Mode) |
| **Service stealth** | UDP Gatekeeper with Single Packet Authorization |
| **No harvest attack surface** | Only semantic-free integers are transmitted |
| **Sovereign** | No CAs, no directory services, no third-party trust |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Field Provisioning Bundle                   │
│  seed σ │ topology seed │ pepper │ vocabulary │ session state   │
└────┬────┴───────┬───────┴───┬────┴──────┬─────┴───────┬────────┘
     │            │           │           │             │
     ▼            ▼           ▼           ▼             ▼
  Fingerprint  Ghost      Weight     VocabCodec    Epoch Anchor
  Bits (B)     Topology   Hiding     (sovereign)   (chain hash)
     │            │           │           │             │
     └────────────┴───────────┴───────────┴─────────────┘
                              │
                    ┌─────────┴─────────┐
                    │  IDRE Stream Cipher │
                    │  Permute → XOR     │
                    │  HMAC-SHA256 MAC   │
                    └─────────┬─────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
        Dark Mode       Encrypted        Ouroboros
        Gatekeeper      Headers          Ratchet
        (SPA)           + Route Tags     (forward secrecy)
```

## Repo Layout

```
core/                      # Crypto primitives
  field.py                 # Fingerprint scan (bits B)
  primitives.py            # Per-block salt, keystream, permutation, XOR
  frozen_physics.py        # Deterministic frozen backend
  session.py               # Replay window + session tracking
  wire.py                  # Canonical JSON AAD + wire framing
  neural_codec.py          # Session-bound Hebbian compression

hive/                      # Protocol layer
  node.py                  # FieldBoundNode (send/receive/handshake)
  server.py                # HTTP handler
  client.py                # HiveClient
  protocol.py              # Route tags, header encryption
  knock.py                 # SPA knock packets
  gatekeeper.py            # UDP Gatekeeper proxy

tests/                     # 55 unit tests
  test_core.py             # Core crypto (18 tests)
  test_hive.py             # Protocol (5 tests)
  test_node_v12_full.py    # Full v1.2 node (12 tests)
  test_dark_mode.py        # Gatekeeper + SPA (10 tests)
  test_encrypted_header.py # Encrypted headers (10 tests)

attacks/                   # Adversarial test harness
scripts/                   # Demo servers, verification scripts
docs/                      # Paper, threat model, comparison, status
```

## Quickstart

### Install

```bash
pip install numpy   # only external dependency
```

### Run Tests

```bash
python -m pytest tests/ -v
```

All 55 tests should pass. No network, no GPU, no external services required.

### Run 2 Nodes + Attack Suite

```powershell
# Node A
python scripts\hive_v12_node_server.py --port 8890 --node-id A --seed 7245 --anchor-seeds 7245 --freeze-field

# Node B
python scripts\hive_v12_node_server.py --port 8891 --node-id B --seed 7245 --anchor-seeds 7245 --freeze-field --print-deliveries

# Black-box attack suite
python attacks\idre_http_attack_suite.py --node-a http://127.0.0.1:8890 --node-b http://127.0.0.1:8891
```

## How It Works

1. **Fingerprint derivation**: Seed → deterministic vector field → geometric scan → binary fingerprint $B$ (288 bits)
2. **Weight hiding**: $B' = \text{HMAC}(\text{pepper}, B)$ — non-differentiable trapdoor
3. **Per-block encryption**: Salt → permutation $\pi_k$ + keystream $K_k$ → `Permute(plaintext) ⊕ keystream`
4. **Authentication**: `HMAC-SHA256(mac_key, AAD ‖ ciphertext)`
5. **Anti-replay**: Nonce window + Epoch Anchor chain hash

The wire format transmits only integers. No plaintext, no key shares, nothing to harvest.

## Security Layers

Each layer is independently composable — operators choose depth based on their threat model:

| Layer | What It Does | Can Be Disabled? |
|:---|:---|:---|
| Fingerprint + Pepper | Core keying material | No (required) |
| Permute→XOR cipher | Payload confidentiality | No (required) |
| HMAC-SHA256 | Integrity + authenticity | No (required) |
| Ghost Topology | Geometric obfuscation | Yes |
| VocabCodec | Network domain separation | Yes |
| Neural Codec | Traffic shape obfuscation | Yes |
| Epoch Anchor | Anti-rollback chain hash | Yes |
| Ouroboros Ratchet | Forward secrecy | Yes |
| Encrypted Headers | Metadata confidentiality | Yes |
| Dark Mode Gatekeeper | Service stealth + DoS defense | Yes |

## Documentation

| Document | Purpose |
|:---|:---|
| [STATUS.md](docs/STATUS.md) | Blunt current state vs goal |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | What we protect, what we assume, what we don't claim |
| [COMPARISON.md](docs/COMPARISON.md) | IDRE vs TLS 1.3, WireGuard, Signal |
| [IDRE Paper v2.4](docs/IDRE-PAPER) | Full protocol specification + security analysis |

## Important Warnings

- **Research prototype** — not independently audited.
- **The Field Provisioning Bundle is key material.** If it leaks, confidentiality is lost.
- **Forward secrecy** is limited to Ouroboros Ratchet events; no ephemeral DH.
- **Side channels** are excluded from the adversary model (Python is not constant-time).
- **Float determinism**: threshold binarization provides margin, but cross-architecture calibration is recommended.

## Verification Scripts

| Script | What It Proves |
|:---|:---|
| `scripts/verify_real_stream.py` | Bidirectional stream + Toxic Eve injection → all rejected |
| `scripts/verify_epoch_anchor.py` | Chain hash binds packets; one drop → instant lockout |
| `scripts/verify_resonant_drift.py` | Eve clone drifts out of sync via neural plasticity |
| `scripts/verify_replay_clone.py` | Determinism proof: perfect clone stays in sync (forward secrecy requires packet loss) |
| `attacks/idre_http_attack_suite.py` | Black-box HTTP attack harness |
| `attacks/idre_rate_limit_suite.py` | Rate limiting smoke test |
| `attacks/cryptanalysis/main.py` | Full Chosen-Plaintext / Statistical Cryptanalysis Suite |

## License

[Apache License 2.0](LICENSE)

Copyright 2026 Miguel Alejandro Morelo Bustamante
