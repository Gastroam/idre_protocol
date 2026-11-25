# IDRE v3 Profile and Wire Specification (Task 1)

**Version:** `IDRE/3.0`  
**Status:** Frozen profile and wire contract for Milestone M0–M3. Does not claim completed cryptographic proof or v3 benchmark results.

## 1. Recorded Owner Decisions (D1–D6)

| ID | Topic | Locked Decision | Scope Note |
| --- | --- | --- | --- |
| **D1** | State scope | `per_session_direction` — separate mutable field, chain, sequence, and codec per session direction (`i2r`, `r2i`) | Network-global field requires a separate ordered group-update protocol |
| **D2** | Pointer meaning | `wire_field_bound_m1` — M1 field-bound wire protection is the target for M1–M3 | Intrinsic inner-pointer dependence remains a separate research gate (Task 11) |
| **D3** | Cryptographic foundation | `HKDF-SHA256+CHACHA20-POLY1305` in `hive/` | `core/` remains strictly `numpy` + Python stdlib; key schedule reviewed in Task 5 |
| **D4** | Learning & numerics | `fixed_point_i64_q16` with `constant_stimulus_v1` | Cross-platform deterministic; message-conditioned stimulus deferred to a separate versioned profile |
| **D5** | Initial reliability | `stop_and_wait` (`max_in_flight = 1`) per direction, durable outbox/inbox, authenticated idempotent ACKs | Windowed delivery deferred |
| **D6** | Compromise scope | `shared_network_root_outsider` — protects against outsiders who lack provisioning | No insider-vs-insider isolation yet; no broad forward-secrecy/PCR claim until audited |

## 2. Protocol Version Selection and Anti-Downgrade Policy

- Explicit version selection is required (`v2` vs `v3`).
- `v2` defaults and behavior remain unchanged for reproduction and legacy compatibility.
- Selecting `v3` MUST NOT silently fall back to `v2`, `frozen` backend, `utf8` codec, literal vocabulary escapes, `multiverse` healing, or seed-only offline recovery.
- Any profile validation failure fails closed and constructs no live session.

## 3. Roles, Directions, and Identifier Widths

| Field | Type / Width | Canonical Encoding / Values |
| --- | --- | --- |
| `protocol_version` | UTF-8 string | `"IDRE/3.0"` |
| `role` | UTF-8 string | `"initiator"` (`0x00`) or `"responder"` (`0x01`) |
| `direction` | `uint8` (1 byte) | `"i2r"` (`0x00`, initiator → responder) or `"r2i"` (`0x01`, responder → initiator) |
| `bundle_id` | 16 bytes | Opaque public deployment identifier; MUST NOT equal `expected_vocab_digest[:16]` |
| `expected_vocab_digest` | 32 bytes | Private SHA-256 over `"IDRE-VOCAB-V3\x00strict_vocab_v3\x00"` + length-prefixed UTF-8 tokens |
| `session_id` | 16 bytes | 128-bit session identifier |
| `initiator_nonce` / `responder_nonce` | 32 bytes each | OS CSPRNG fresh handshake contributions from both endpoints |
| `network_secret` / `field_init_secret` | >= 32 bytes each | OS CSPRNG provisioning secrets (never a short seed or neuron ID) |
| `epoch` | `uint32` (4 bytes) | Big-endian unsigned integer (`0..2^32-1`) |
| `seq` | `uint64` (8 bytes) | Big-endian unsigned integer (`0..2^64-1`); wraparound closes direction |
| `msg_type` | `uint8` (1 byte) | `0x01=HANDSHAKE_INIT`, `0x02=HANDSHAKE_RESP`, `0x03=DATA`, `0x04=ACK`, `0x05=EPOCH_CTRL` |

## 4. Frozen Wire Layout and Cell Capacity (4096-Byte Bound)

The maximum wire cell is fixed at **4096 bytes**. Every v3 frame has a fixed 54-byte outer header followed by an AEAD ciphertext (which includes a 16-byte Poly1305 tag; the 12-byte AEAD nonce is derived from the Task 5 key schedule and is not transmitted raw).

```text
Offset  Size  Field
------  ----  ----------------------------------------------------------
0       4     magic            = b"IDR3"
4       1     version          = 0x03
5       1     msg_type         = 0x01..0x05
6       1     flags            = bit0: encrypted_header, bit1: adaptive_codec
                                 (bits 2..7 MUST be 0)
7       1     direction        = 0x00 (i2r) | 0x01 (r2i)
8       16    bundle_id        = opaque public bundle identifier
24      16    session_id       = 128-bit session identifier
40      4     epoch            = uint32 big-endian
44      8     seq              = uint64 big-endian
52      2     ciphertext_len   = uint16 big-endian (includes 16B AEAD tag)
------  ----  ----------------------------------------------------------
Total outer header: 54 bytes
```

### Exact Usable Payload Capacity

- `MAX_WIRE_CELL_BYTES = 4096`
- `WIRE_HEADER_BYTES = 54`
- `AEAD_TAG_BYTES = 16` (ChaCha20-Poly1305)
- `CODEC_FRAMING_OVERHEAD_BYTES = 3` (1-byte `OP_LITERAL` + 2-byte `uint16` length)
- `ENCRYPTED_HEADER_OVERHEAD_BYTES = 80` (16-byte route tag + 48-byte encrypted header + 16-byte tag, when `encrypted_headers=True`)

Therefore:
- Maximum AEAD ciphertext (`ciphertext_len`): `4096 - 54 = 4042` bytes
- Maximum AEAD plaintext: `4042 - 16 = 4026` bytes
- Maximum usable strict-vocab payload (standard headers): `4026 - 3 = 4023` bytes
- Maximum usable strict-vocab payload (encrypted headers): `4023 - 80 = 3943` bytes

`ProfileV3.max_plaintext_bytes` MUST NOT exceed this computed usable capacity. The legacy 65535-byte allowance is rejected in v3.

## 5. Strict Decoding & Privacy Rules

1. **Strict vocabulary only:** `content_codec` MUST be `"vocab"` and `vocab_allow_literals` MUST be `False`.
2. **Private digests stay private:** `expected_vocab_digest` and field-derived digests are private inputs bound into the handshake/KDF transcript; they are never emitted as public identifiers (`bundle_id` is opaque).
3. **Immutable parameters:** Geometry, numeric profile, learning parameters, and anchor IDs are frozen in `ProfileV3` and bound into `TranscriptV3` via `canonical_profile(profile)`.
4. **Oversize rejection:** Any input whose encoded payload exceeds `max_plaintext_bytes` or whose frame exceeds `max_wire_cell_bytes` MUST fail before mutating field, codec, sequence, or outbox state.
