# IDRE Clean

Minimal, testable extraction of **IDRE/Hive v1.2**:

- **IDRE**: a field-bound security protocol that sends semantic-free integers on the wire.
- **IDRE-Silence**: an optional *offline transport* that carries already-secured IDRE bytes through audio.

## What IDRE Is (In This Repo)

At a high level, IDRE binds decoding capability to a non-exportable receiver state (a frozen attractor/field).
Instead of sending plaintext, nodes exchange integer payloads that are only meaningful for receivers with the
same field geometry.

This implementation provides:
- Field-bound identity check (handshake proves "same field").
- Integer-only payloads (no plaintext on the wire).
- Framing that tolerates appended noise (ignored by design).
- Replay rejection (per-session nonce window).
- Tamper rejection (HMAC over header AAD + ciphertext bytes).
- **Handshake anti-replay** (one-time challenge; prevents session fixation after restart).
- **Freshness control** (`created_at_ms` / `expires_at_ms` in header AAD).
- **Basic DoS guards** (rate limiting on handshake endpoints + bounded pending challenges).
- **Vocab/token payloads** (optional): deterministically encode text into token indices using a shared positional vocab.
- **Offline sealed letters** (sessionless): time-bounded envelope (`IDRE-OFFLINE/1`) suitable for audio transport.

## Important Non-Goals / Warnings

- This is **not** a formally audited cryptosystem.
- IDRE-Silence is **transport only** (CRC + optional repetition FEC). It does not replace IDRE security.
- "Private physics" is **key material**. If it leaks, confidentiality is lost (symmetric-key reality).

## Reading Order

- `STATUS.md`: blunt current state vs goal.
- `THREAT_MODEL.md`: what we protect, what we assume, what we don't claim.
- `ROADMAP.md`: future-proofing plan (PQ, DDoS, compliance, offline hardening, LLM role).

## Repo Layout (What Matters)

- `core/`
  - `field.py`: fingerprint scan (bits `B`) for a seed/field.
  - `primitives.py`: per-block salt, keystream + permutation derivation, XOR/permute.
  - `session.py`: replay window (`NonceWindow`) + session tracking.
  - `wire.py`: canonical JSON AAD + wire framing `[ct_len][ct][tag][noise...]`.
- `hive/` (Modular Server):
  - `node.py`: FieldBoundNode logic.
  - `server.py`: HTTP Handler.
  - `client.py`: HiveClient for robust HTTP interactions.
  - `cli.py`: Shared argument parsing.
- Reference server + demo scripts:
  - `scripts/hive_v12_node_server.py`
  - `scripts/hive_v12_full_workflow_demo.py`
- Attack harness:
  - `attacks/idre_http_attack_suite.py`
- Offline transport (audio):
  - `transports/idre_silence.py`
  - `transports/idre_silence_cli.py`
  - `transports/test_idre_silence_robustness.py`

## Quickstart: Run 3 Nodes + Attack Suite

Start nodes (same field for A/B, different seed for EVE):

```powershell
Set-Location <repo-root>

python scripts\hive_v12_node_server.py --port 8890 --node-id A --seed [SEEDS] --anchor-seeds [ANCHOR_SEEDS] --freeze-field --print-deliveries
python scripts\hive_v12_node_server.py --port 8891 --node-id B --seed [SEEDS] --anchor-seeds [ANCHOR_SEEDS] --freeze-field --print-deliveries
python scripts\hive_v12_node_server.py --port 8892 --node-id EVE --seed [SEEDS] --anchor-seeds [ANCHOR_SEEDS] --freeze-field --print-deliveries
```

Run the black-box HTTP attack suite:

```powershell
python attacks\idre_http_attack_suite.py --node-a http://127.0.0.1:8890 --node-b http://127.0.0.1:8891 --node-e http://127.0.0.1:8892
```

Run the slow add-ons (challenge expiry + session TTL expiry):

```powershell
python attacks\idre_http_attack_suite.py --node-a http://127.0.0.1:8890 --node-b http://127.0.0.1:8891 --node-e http://127.0.0.1:8892 --slow
```

## Security Verification

We provide rigorous verification scripts to validate the protocol's claims:

1.  **Bidirectional Stream & Toxic Eve (`verify_real_stream.py`)**:
    -   Establishes A<->B full-duplex stream.
    -   Spawns "Toxic Eve" to inject malformed packets, replay traffic, and fuzz fields.
    -   **Result**: Nodes reject all tampering/replay attempts.

2.  **Epoch Anchor (`verify_epoch_anchor.py`)**:
    -   Verifies that every packet binds to the session history via `ChainHash`.
    -   Simulates packet loss (Eve drops packet N).
    -   **Result**: Eve is instantly locked out at packet N+1 (MAC mismatch due to wrong chain state).

3.  **Resonant Drift (`verify_resonant_drift.py`)**:
    -   Demonstrates continuous forward secrecy via neural plasticity.
    -   **Result**: Eve (clone) drifts out of sync over time as the lattice evolves uniquely for the active participants.

## Content Codec: UTF-8 vs Vocab Tokens

By default, nodes send UTF-8 plaintext bytes through IDRE encryption/MAC.
If both endpoints share the same positional vocab file, you can send a compact token stream instead (with literal fallback):

```powershell
python scripts\hive_v12_node_server.py --port 8890 --node-id A --seed 7245 --anchor-seeds 7245 --freeze-field --content-codec vocab --vocab-file F:\idre_clean\vocab.jsonl
python scripts\hive_v12_node_server.py --port 8891 --node-id B --seed 7245 --anchor-seeds 7245 --freeze-field --content-codec vocab --vocab-file F:\idre_clean\vocab.jsonl --print-deliveries
```

Strict vocab mode (recommended for lab/protocol work) rejects any out-of-vocab characters/segments:

```powershell
python scripts\hive_v12_node_server.py --port 8890 --node-id A --seed [SEEDS] --anchor-seeds [ANCHOR_SEEDS] --freeze-field --content-codec vocab --vocab-file F:\idre_clean\vocab.jsonl --no-vocab-allow-literals
python scripts\hive_v12_node_server.py --port 8891 --node-id B --seed [SEEDS] --anchor-seeds [ANCHOR_SEEDS] --freeze-field --content-codec vocab --vocab-file F:\idre_clean\vocab.jsonl --no-vocab-allow-literals --print-deliveries
```

Notes:
- `vocab.jsonl` is the preferred format (streaming load, diff-friendly).
- The vocab has an embedded `vocab_id`; mismatch is rejected (`wrong_vocab`), not guessed.

To generate a `vocab.jsonl` from a HuggingFace tokenizer, use `scripts/extract_vocab_from_tokenizer_json.py`.

## Open Internet Mode (Gateway + Fixed-Size Cells)

For a global passive observer threat model, keep the IDRE node **localhost-only** and put a separate gateway in front that:
- sends fixed-size cells at a constant rate (cover traffic)
- carries real IDRE messages inside those cells
- can be exposed through Tor/I2P tunnels without exposing the node

Gateway endpoints:
- `POST /cell` (octet-stream, fixed-size)
- `POST /enqueue` (JSON, local operator API)

Local smoke test (spawns 2 nodes + 2 gateways on ephemeral ports):

```powershell
python attacks\idre_gateway_smoke.py
```

Manual run (LAN, no Tor/I2P):

```powershell
# Nodes (localhost-only)
python scripts\hive_v12_node_server.py --port 8890 --node-id A --seed 7245 --anchor-seeds 7245 --freeze-field
python scripts\hive_v12_node_server.py --port 8891 --node-id B --seed 7245 --anchor-seeds 7245 --freeze-field --print-deliveries

# Gateways (these are the Internet-facing components in real deployments)
python scripts\idre_gateway.py --listen 127.0.0.1:9010 --node http://127.0.0.1:8890 --peer-cell-url http://127.0.0.1:9011/cell --tick-hz 10 --cell-len 1024
python scripts\idre_gateway.py --listen 127.0.0.1:9011 --node http://127.0.0.1:8891 --peer-cell-url http://127.0.0.1:9010/cell --tick-hz 10 --cell-len 1024

# Enqueue an outbound message at Gateway A (requires A<->B handshake already established)
python -c "import json,urllib.request; u='http://127.0.0.1:9010/enqueue'; d=json.dumps({'dst_node_id':'B','content':'hello'}).encode(); print(urllib.request.urlopen(urllib.request.Request(u,data=d,headers={'Content-Type':'application/json'},method='POST')).read().decode())"
```

## How IDRE Works Here (Mechanically)

This repo's v1.2 wire format is:

1. **Header (JSON)**: `src/dst/session_id/nonce/created_at_ms/expires_at_ms/...` (plaintext metadata, authenticated by MAC)
2. **Payload (integers)**: `[ct_len][ct_bytes...][tag(32 bytes)][noise...]`
   - `ct_len` bounds parsing.
   - `tag` is `HMAC-SHA256(mac_key, aad || ct_bytes)`.
   - Any bytes after `tag` are treated as noise/padding and ignored.

The "key" material is derived deterministically from the receiver field fingerprint bits `B` plus session context
(session id, ephemeral salt, nonce). There is no exported static key blob, but there *is* effective keying material
inside the field geometry, which is the point of the design.

## Time Sync (NTP)

Time controls (`created_at_ms` / `expires_at_ms`) assume nodes have reasonably synchronized clocks.
For robust operation, run all nodes on an NTP-synchronized system clock (UTC epoch ms).

Quick drift check (compares each node to your local machine):

```powershell
python scripts\\idre_time_check.py http://127.0.0.1:8890 http://127.0.0.1:8891 --warn-ms 30000
```

Tune enforcement via `scripts/hive_v12_node_server.py` flags:
- `--skew-ms` (default 120000)
- `--default-ttl-ms` and `--max-ttl-ms`

## Offline Transport: IDRE-Silence (Audio Carrier)

`IDRE-Silence` converts **bytes** into an audio "hum" using prime-gap timing between zero-crossings, with:
- CRC32 framing (detects corruption).
- Optional bit repetition FEC (`fec_repeat`) for robustness under heavy noise/jitter/dropouts.

Encode a long letter/report to WAV (no SciPy required):

```powershell
python transports\idre_silence_cli.py encode --profile stealth_100hz --fec-repeat 3 --compress --verify --in-file path\to\report.txt --out-wav logs\report.wav
```

Decode WAV back to bytes:

```powershell
python transports\idre_silence_cli.py decode --profile stealth_100hz --fec-repeat 3 --in-wav logs\report.wav --out-file recovered.txt
```

To carry IDRE over audio:
1. Produce the secured IDRE wire frame as `bytes`.
2. `encode_bytes(wire_bytes) -> audio`
3. Transport/store audio.
4. `decode_bytes(audio) -> wire_bytes`
5. Deliver the recovered `wire_bytes` to the receiver node for normal IDRE verification/decrypt.

## Offline "Sealed Letter" (Sessionless)

If you want one-way offline delivery that **does not require an online session**, use the gateway:

```powershell
python scripts\\idre_offline_gateway.py encode-letter --seed 7245 --in-file path\\to\\report.txt --out-wav logs\\report.wav --compress
python scripts\\idre_offline_gateway.py decode-letter --seed 7245 --in-wav logs\\report.wav --out-file logs\\report.decoded.txt
```

This produces a self-contained `IDRE-OFFLINE/1` envelope (MAC + time window) and then carries it through IDRE-Silence WAV.

### Offline + Vocab (Strict)

You can also seal tokenized text offline (vocab payload inside the sealed envelope), then carry it through audio:

```powershell
python scripts\idre_offline_gateway.py encode-text-vocab --seed 7245 --vocab-file F:\idre_clean\vocab.jsonl --no-vocab-allow-literals --compress --in-file path\to\report.txt --out-wav logs\report.vocab.wav
python scripts\idre_offline_gateway.py decode-text-vocab --seed 7245 --vocab-file F:\idre_clean\vocab.jsonl --no-vocab-allow-literals --in-wav logs\report.vocab.wav --out-file logs\report.decoded.txt
```

Implementation notes:
- The offline envelope framing uses a **u32** ciphertext length prefix (safe for large payloads).
- The audio decoder uses a prefix check (`IDREOFF1`) to reduce CRC false positives on long recordings.
- On Windows, the offline gateway normalizes BOM/CRLF for strict vocab encoding (prevents invisible-char failures).

## Resonant Security Demo (Continuous Forward Secrecy)

To demonstrate the "Living Security" paradigm where encryption keys evolve via neural lattice plasticity:

1.  **Start Nodes A and B** with plasticity enabled (they will learn from each packet):

```powershell
# Node A
python scripts\hive_v12_node_server.py --port 8900 --node-id A --seed 7245 --planes 4 --backend lattice --enable-plasticity --content-codec vocab --vocab-file vocab.jsonl --print-events

# Node B
python scripts\hive_v12_node_server.py --port 8901 --node-id B --seed 7245 --planes 4 --backend lattice --enable-plasticity --content-codec vocab --vocab-file vocab.jsonl --print-events
```

2.  **Run the Verification Script**:
    This script launches an "Eve" clone (same seed, same config) and observes traffic.
    - It validates a mutual handshake (A<->B).
    - It sends traffic A->B for 60 seconds.
    - It proves that Eve **fails to decrypt** the final message because her lattice state has drifted from the active conversation.

```powershell
python scripts\verify_resonant_drift.py --existing-nodes
```

3.  **The Ultimate Test: Replay-Clone Attack** (`verify_replay_clone.py`)
    -   Spawns an Eve node initialized with the **exact same seed** as B, manually synced to the session, and fed 100% of the traffic.
    -   **Result**: Eve **SUCCEEDS** in maintaining sync.
    -   **Implication**: The system is **Deterministic**. True Forward Secrecy relies on **Packet Loss** (Partial Take). If Eve misses a packet, her state diverges irreversibly.

4.  **The Epoch Anchor** (State-Tethered Validity):
    -   Every message is cryptographically bound to the entire history of the session (`ChainHash`).
    -   Missing **one packet** causes immediate HMAC failure on all subsequent packets.
    -   Enforces "Hard Lockout" for divergent clones.

## Operational Hardening Knobs (Demo Server)

This repo's server (`scripts/hive_v12_node_server.py`) is a protocol demo, but it includes a few pragmatic guards:

- Rate limiting (per-client IP) on:
  - `POST /hive/v12/challenge`
  - `POST /hive/v12/verify_req/process`
- Bounded in-memory `pending_challenges` with expiry/used cleanup and oldest eviction.

Tune via CLI flags:

```powershell
python scripts\hive_v12_node_server.py --port 8890 --node-id A --seed 7245 --anchor-seeds 7245 --freeze-field --backend frozen `
  --max-pending-challenges 8192 `
  --rl-challenge-rps 10 --rl-challenge-burst 20 `
  --rl-verify-rps 8 --rl-verify-burst 16
```

Smoke-test the rate limits (spawns its own node and hammers the endpoints):

```powershell
python attacks\idre_rate_limit_suite.py
```
