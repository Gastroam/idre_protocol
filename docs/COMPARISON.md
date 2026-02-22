# IDRE Protocol Comparison (v2.4)

How IDRE compares to TLS 1.3, WireGuard, and Signal — and where it doesn't compete.

## Scope Note

IDRE targets **sovereign, pre-provisioned networks** where out-of-band key provisioning is acceptable and third-party trust (PKI/CAs) is not. It does **not** solve key distribution over untrusted networks. The comparisons below are fair only within IDRE's target deployment environment.

## Feature Matrix

| Feature | **IDRE v2.4** | **TLS 1.3** | **WireGuard** | **Signal** |
|:---|:---|:---|:---|:---|
| **Trust Model** | Sovereign (out-of-band provisioning) | Centralized (CA system) | Peer-to-peer (PSK or PKI) | Centralized directory |
| **Key Exchange** | None (pre-provisioned bundle) | Ephemeral DH / PSK | Static + Ephemeral DH | X3DH + Double Ratchet |
| **Symmetric Cipher** | SHA256-CTR + Permute→XOR | AES-GCM / ChaCha20-Poly1305 | ChaCha20-Poly1305 | AES-CBC / ChaCha20 |
| **Authentication** | HMAC-SHA256 | AEAD (built-in) | Poly1305 | HMAC-SHA256 |
| **Post-Quantum** | Native (no asymmetric ops) | Vulnerable (Shor's) | Vulnerable | Vulnerable |
| **Forward Secrecy** | Ouroboros Ratchet (event-triggered) | Perfect (ephemeral DH) | Perfect (key rotation) | Perfect (Double Ratchet) |
| **Metadata Protection** | Encrypted headers + rotating route tags | None (SNI visible) | Minimal | Sealed sender (opt-in) |
| **Traffic Analysis** | Neural Codec + padding | Content encrypted, size visible | Fixed-size padding | Padding |
| **DoS Mitigation** | Dark Mode SPA + per-IP rate limiting | Client puzzles / cookies | Cookie reply | Various |
| **Partial Compromise** | Graceful degradation (multi-layer) | Full compromise | Full compromise | Ratchet limits damage |
| **Provisioning Complexity** | High (multi-component bundle) | Low (certificate + key) | Low (keypair) | Low (registration) |
| **Maturity** | Research prototype | RFC 8446 (battle-tested) | RFC (audited) | Peer-reviewed |

## Detailed Comparison

### 1. The Quantum Threat (Harvest Now, Decrypt Later)

- **TLS/WireGuard/Signal**: Rely on elliptic curve or RSA key exchange — vulnerable to Shor's algorithm. PQC migration (Kyber, ML-KEM) is underway but adds overhead and is not yet widely deployed.
- **IDRE**: No asymmetric operations. No keys on the wire. Security reduces to symmetric primitives (SHA256, HMAC-SHA256). Grover's algorithm halves effective bit-depth; with ≥256-bit bundle entropy, this remains infeasible. **IDRE is post-quantum by construction.**

### 2. AI/ML Cryptanalysis

- **Standard ciphers**: AES and ChaCha20 are highly non-linear and resistant to current ML attacks.
- **IDRE**: The raw geometric scan is a linear projection — vulnerable to gradient descent. The **pepper** (§2.2) applies an HMAC trapdoor making the derivation non-differentiable. Post-pepper, IDRE matches standard symmetric hardness.

### 3. Forward Secrecy

- **TLS/WireGuard/Signal**: Perfect forward secrecy via ephemeral key exchange. Compromise of long-term key does not expose past sessions.
- **IDRE**: Forward secrecy is provided by the **Ouroboros Ratchet** (§3.9), which rotates keys on external consensus events. This is weaker than ephemeral DH — if the root bundle is compromised and no ratchet event has occurred, past traffic is exposed. **Trade-off**: IDRE avoids online key exchange (and its metadata leakage) at the cost of weaker PFS.

### 4. Metadata Protection

- **TLS**: SNI, certificate, and connection metadata are visible. ESNI/ECH are in draft.
- **WireGuard**: Minimal metadata leakage; IP headers visible.
- **Signal**: Sealed sender hides sender identity (opt-in).
- **IDRE**: **Encrypted headers** hide all protocol metadata (`src/dst/session_id/nonce/timestamps`). **Rotating route tags** provide unlinkable external routing identifiers that change every epoch. **Dark Mode Gatekeeper** makes the service port invisible to scanners.

### 5. Partial Compromise Resilience

- **Standard protocols**: Compromise of the single key/certificate exposes everything.
- **IDRE**: The Field Provisioning Bundle has 5 independent dimensions (seed, topology, pepper, vocabulary, session state). Compromising any single dimension without the others yields noise. This **graceful degradation** is a structural property no single-key protocol can match.

## Where IDRE Does Not Compete

- **Public internet**: IDRE requires out-of-band provisioning. It cannot replace TLS for web traffic.
- **Open federation**: IDRE networks are closed by design. No equivalent to certificate transparency or key directory.
- **Maturity**: IDRE is a research prototype with 55 tests. TLS has decades of cryptanalysis, formal proofs, and real-world deployment.
- **Ease of deployment**: IDRE's multi-component provisioning is operationally heavier than generating a keypair.

## Summary

IDRE trades **provisioning simplicity** for **quantum resistance**, **metadata protection**, **partial-compromise resilience**, and **sovereign control**. It is purpose-built for closed, high-security networks where pre-provisioning is acceptable and third-party trust is not.
