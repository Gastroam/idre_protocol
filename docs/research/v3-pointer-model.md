# IDRE v3 Inner-Pointer Research Model & Decision (Task 11)

**Status:** Laboratory research artifact. Not promoted into `IDRE/3.0` (`wire_field_bound_m1`).

## 1. Exposure Game (P7: Intrinsic Pointer-State Dependence)

- **Given to attacker:** Inner pointer bytes after removal of outer AEAD protection, the complete fixed vocabulary (`tokens[0..N-1]`), `chain_secret`, `dict_key`, and public message context `(session_id, direction, epoch, seq, token_pos)`.
- **Hidden from attacker:** Current private canonical `FieldStateV3` (and its derived `FieldViewV3.binding_bytes`).
- **Capability boundary:** Any derived pointer key extracted from memory is an equivalent capability; software pointers cannot require physical possession of the full weight array after key extraction.

## 2. Evaluated Invertible Candidates

Implemented in [pointer_candidates.py](../../benchmarks/v3/pointer_candidates.py) and tested in [test_pointer_candidates.py](../../tests/v3/test_pointer_candidates.py):

1. **`FeistelPointerV3` (Candidate A):** 4-round balanced Feistel permutation with cycle-walking over exact domain `0..N-1`, keyed by `FieldViewV3.binding_bytes` and domain-separated per `(context, token_pos)`.
   - **Inversion & Collisions:** 100% bijective (`0` collisions) across arbitrary `N >= 2`; `O(1)` memory and **expected `O(1)`** encode/decode time (cycle-walking averages `< 4` iterations because `N > 2^(total_bits - 2)`, though worst-case iteration count is probabilistic rather than strict worst-case `O(1)`).
   - **Small-domain security caveat:** A 4-round balanced Feistel network is **not** a proven strong PRP on tiny domains (e.g., `N = 4`, 2-bit halves) where Luby-Rackoff bounds do not apply. Any production small-domain inner-pointer scheme would require a reviewed small-domain FPE construction (e.g., Swap-or-Not or NIST SP 800-38G FF1 with a sufficient domain) rather than 4-round Feistel.
   - **Repeated-token leakage:** Eliminated across positions because `token_pos` is bound into every round; reusing `(state, context, token_pos)` leaks equality (proving per-position freshness is mandatory).
   - **Wrong-field behavior:** Produces a pseudorandom wrong index (requires outer AEAD or inner integrity tag to reject cleanly).
2. **`KeyedHashPermutationBaseline` (Candidate B):** Identical Feistel bijection keyed by a 32-byte SHA-256 hash-state instead of the 64-dim neural field.
   - Achieves the **exact same P7 functional property** at identical per-token cost and lower state overhead.
3. **`PrfTagLookupPointer` (Candidate C):** 64-bit truncated HMAC tag `HMAC(binding_bytes, context || token_pos || idx)[:8]`.
   - Immediately rejects wrong-field decoding (`None`), but requires an `O(N)` reverse scan or `O(N)` per-position table — prohibitive for realistic vocabularies.

## 3. Explicit Research Decision

- **Functional feasibility:** `FeistelPointerV3` satisfies the P7 functional interface (invertible, zero-collision, O(1) memory, per-position unlinkable inner pointers requiring current state capability even when the fixed vocabulary is known).
- **Neural uniqueness (G4):** Because `KeyedHashPermutationBaseline` achieves the identical P7 property under the same 32-byte entropy budget, intrinsic pointer hiding is a property of **keyed per-position format-preserving encryption**, not a unique property of neural weights.
- **Protocol decision:** Retain **M1 (`wire_field_bound_m1`)** as the frozen `IDRE/3.0` shipping profile per owner decision D2. Keep `FeistelPointerV3` archived as an experimental laboratory reference (`IDRE/3.1-exp-pointer`) without claiming neural cryptographic novelty.
