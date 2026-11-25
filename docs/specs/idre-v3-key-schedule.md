# IDRE v3 Field-Dependent Key Schedule Specification (Task 5)

**Suite:** `HKDF-SHA256+CHACHA20-POLY1305` (RFC 5869 / RFC 8439)  
**Status:** Candidate construction for Milestone M1. Requires independent cryptographic review before G3 sign-off.

## 1. Security & Assumption Boundaries

- **Entropy source:** Relies on `network_secret` (>= 32 bytes) and `field_init_secret` (>= 32 bytes) from an OS CSPRNG. HKDF-SHA-256 concentrates existing entropy; it does **not** claim additional independent entropy from deterministic neural field evolution.
- **No ratchet-only bypass:** Every established-session DATA key derivation (`derive_message_keys`) requires BOTH the current directional `chain_secret` (32 bytes) AND the current pre-message canonical `FieldViewV3` (32-byte private binding over full `FieldStateV3`). There is no optional field parameter and no ratchet-only DATA constructor.
- **Key commitment boundary:** Standard ChaCha20-Poly1305 (RFC 8439) does not by itself prove adversarial key commitment under attacker-chosen keys (RFC 9771). Passing KAT tests is not a proof of adversarial key commitment.
- **Non-exportability boundary:** Derived message keys and field bindings are equivalent capabilities in software under full endpoint compromise. Private bindings are never emitted in wire headers or diagnostic logs.

## 2. Transcript & Session Initialization

Given `ProvisioningBundleV3` and `TranscriptV3`:

```text
transcript_hash = SHA-256(transcript.canonical_bytes())
session_root    = HKDF-SHA256(ikm=network_secret, salt=transcript_hash,
                              info="IDRE-V3-SESSION-ROOT", L=32)
```

For each direction `d in {"i2r", "r2i"}`:

```text
chain_secret[d] = HKDF-SHA256(ikm=session_root, salt=transcript_hash,
                              info="IDRE-V3-CHAIN-INIT|" || d, L=32)
field_seed[d]   = HKDF-SHA256(ikm=field_init_secret, salt=transcript_hash,
                              info="IDRE-V3-FIELD-SEED|" || d, L=32)
dict_key[d]     = HKDF-SHA256(ikm=session_root, salt=transcript_hash,
                              info="IDRE-V3-DICT-KEY|" || d, L=32)
field[d]        = initialize_field(profile, field_seed[d],
                                   "dir:" || d || ":" || transcript_hash)
```

## 3. Mutual Handshake Confirmation

Both peers compute a 32-byte HMAC-SHA-256 confirmation tag over the transcript hash, their explicit role (`"initiator"` or `"responder"`), and the initial canonical `FieldViewV3` bindings of both directions:

```text
confirm_key = HKDF-SHA256(ikm=network_secret || field_init_secret,
                          salt=transcript_hash,
                          info="IDRE-V3-HANDSHAKE-CONFIRM-KEY", L=32)

confirm_tag(role) = HMAC-SHA256(confirm_key,
    "IDRE-V3-CONFIRM|" || role || "|" || transcript_hash
    || view(field["i2r"]).binding_bytes
    || view(field["r2i"]).binding_bytes)
```

Because `role` is bound into the tag, an initiator's confirmation cannot be reflected back as a responder's confirmation. A failed verification commits no session or field evolution.

## 4. Per-Message Key Derivation & Chain Advancement

For an immutable pre-message `FieldViewV3`, directional `chain_secret`, and `MessageContextV3`:

```text
ctx_bytes  = context.canonical_bytes()
ctx_salt   = SHA-256(ctx_bytes)
ikm        = chain_secret || view.binding_bytes   (64 bytes)

msg_master = HKDF-SHA256(ikm=ikm, salt=ctx_salt, info="IDRE-V3-MSG-MASTER", L=32)

body_key   || body_nonce   = HKDF-SHA256(ikm=msg_master, salt=ctx_salt, info="IDRE-V3-KEY-BODY",   L=44)
header_key || header_nonce || route_tag
                           = HKDF-SHA256(ikm=msg_master, salt=ctx_salt, info="IDRE-V3-KEY-HEADER", L=60)
ack_key    || ack_nonce    = HKDF-SHA256(ikm=msg_master, salt=ctx_salt, info="IDRE-V3-KEY-ACK",    L=44)
```

Nonce uniqueness is guaranteed because `(session_id, direction, epoch, seq)` is unique per accepted message under stop-and-wait, exact retransmission reuses stored packet bytes rather than re-encrypting, and `seq` wraparound closes the direction.

After message acceptance:

```text
next_chain_secret = HKDF-SHA256(ikm=chain_secret || view.binding_bytes,
                                salt=ctx_salt,
                                info="IDRE-V3-CHAIN-NEXT", L=32)
```
