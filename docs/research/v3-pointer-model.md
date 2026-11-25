# IDRE v3 Inner-Pointer Research Model & Decision (Task 11)

**Status:** Laboratory research artifact. Not promoted into `IDRE/3.0` (`wire_field_bound_m1`).

## 1. Exposure Game (P7: Intrinsic Pointer-State Dependence)

- **Given to attacker:** Inner pointer bytes after removal of outer AEAD protection, the complete fixed vocabulary (`tokens[0..N-1]`), `chain_secret`, `dict_key`, and public message context `(session_id, direction, epoch, seq, token_pos)`.
- **Hidden from attacker:** Current private canonical `FieldStateV3` (and its derived `FieldViewV3.binding_bytes`).
- **Capability boundary:** Any derived pointer key extracted from memory is an equivalent capability; software pointers cannot require physical possession of the full weight array after key extraction.

## 2. Evaluated Invertible Candidates

Implemented in [pointer_candidates.py](../../benchmarks/v3/pointer_candidates.py) and tested in [test_pointer_candidates.py](../../tests/v3/test_pointer_candidates.py):

1. **`FeistelPointerV3` (Candidate A):** 4-round balanced Feistel permutation with cycle-walking over the supported 4-byte index domain (`2 <= N <= 2^32`), keyed by `FieldViewV3.binding_bytes` and domain-separated per `(context, token_pos)`.
   - **Inversion, Space & Cycle-Walking Bounds:** Provides an invertible, collision-free mapping over `2 <= N <= 2^32` using `O(1)` auxiliary space. Let `M` be the padded Feistel domain (`M < 4N`). Over uniformly selected valid input indices, cycle-walking requires at most `M / N < 4` permutation evaluations on average; an individual input can require up to `M - N + 1` evaluations (a deterministic upper bound).
   - **Small-Domain & Security Caveats:** For `N = 4`, the block is 2 bits wide (1-bit left and right halves). Generic 4-round Luby–Rackoff bounds depend on half-block width and become uninformative on tiny halves. Binding `token_pos` into the round inputs provides context separation (whereas reusing `(state, context, token_pos)` leaks exact equality), but context separation and functional bijectivity do **not** by themselves establish PRP security or unlinkability.
   - **Wrong-Field Behavior:** Decoding with a mismatched field produces an in-domain index (which can coincidentally equal the original index); the permutation supplies no pointer-layer authentication and requires outer AEAD or an inner integrity tag.
2. **`KeyedHashPermutationBaseline` (Candidate B):** Identical Feistel bijection keyed by a 32-byte SHA-256 hash-state instead of the 64-dim neural field.
   - Achieves the **exact same P7 functional property** at identical per-token cost and lower state overhead.
3. **`PrfTagLookupPointer` (Candidate C):** 64-bit truncated HMAC tag `HMAC(binding_bytes, context || token_pos || idx)[:8]`.
   - Provides probabilistic wrong-field detection (`None` except under a truncated-tag collision), but requires an `O(N)` reverse scan or `O(N)` per-position table — prohibitive for realistic vocabularies.

## 3. Explicit Research Decision

- **Functional feasibility:** `FeistelPointerV3` satisfies the P7 functional interface (invertible, collision-free mapping over `2 <= N <= 2^32` with `O(1)` auxiliary space and per-position context separation).
- **Neural uniqueness (G4):** Because `KeyedHashPermutationBaseline` achieves the identical functional property under the same 32-byte entropy budget, the demonstrated keyed-permutation property is a property of **keyed per-position format-preserving encryption**, not a unique property of neural weights.
- **Protocol decision:** Retain **M1 (`wire_field_bound_m1`)** as the frozen `IDRE/3.0` shipping profile per owner decision D2. Keep `FeistelPointerV3` archived as an experimental laboratory reference (`IDRE/3.1-exp-pointer`) without claiming PRP security, unlinkability, or neural cryptographic novelty.
