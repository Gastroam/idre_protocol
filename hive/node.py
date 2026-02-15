import hashlib
import hmac
import json
import secrets
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

# Prefer vendored minimal MTI-EVO config
try:
    from idre_clean.vendor.mti_evo.core.config import MTIConfig  # type: ignore
except Exception:
    from mti_evo.core.config import MTIConfig  # type: ignore

from idre_clean.core.frozen_physics import compute_fingerprint_bits_frozen_v12
from idre_clean.core.offline_envelope import open_envelope
from idre_clean.core.wire_bin import pack_receive_envelope, pack_wire_message, unpack_receive_envelope
from idre_clean.core.vocab_codec import (
    Vocab,
    decode_text as vocab_decode_text,
    encode_text as vocab_encode_text,
    load_vocab_registry,
    peek_vocab_id as vocab_peek_vocab_id,
)

from .utils import (
    _sha256, canonical_json, compute_field_profile_id, _now_ms, 
    frame_payload, unframe_payload, 
    pack_plaintext, unpack_plaintext, MAC_LEN, DEFAULT_MAX_CT_LEN, RESONANT_SIGNATURE,
    _expand_bytes,
    DEFAULT_MAX_PAYLOAD_INTS, DEFAULT_MAX_BODY_BYTES, 
    DEFAULT_CHALLENGE_TTL_MS, DEFAULT_SKEW_MS, 
    DEFAULT_MAX_TTL_MS, DEFAULT_DEFAULT_TTL_MS, 
    DEFAULT_MAX_PENDING_CHALLENGES
)
from .physics import (
    derive_locked_planes, seeded_unit_vector, 
    scan_fingerprint_bits, compute_block_salt, derive_keystream_and_permutation, 
    permute, inverse_permute, xor_bytes
)
from .topology import TopologyManager
from .session import HiveSession, PendingChallenge, NonceWindow
from idre_clean.core.neural_codec import NeuralCodec, OP_ACK
from .crypto import (
    crypt_with_bits, derive_mac_key, 
    seal_stream, open_stream,
    _sha256 as crypto_sha256 # internal alias if needed, or just use module
)




@dataclass(frozen=True)
class _FrozenNeuron:
    weights: np.ndarray
    bias: float = 0.0


class FrozenSubstrate:
    """Weights-only substrate for Option A (frozen)."""

    def __init__(self, *, embedding_dim: int, seed_scales: Dict[int, float], bias: float = 0.0, folding_matrix: Optional[np.ndarray] = None):
        self.embedding_dim = int(embedding_dim)
        self.bias = float(bias)
        self._neurons: Dict[int, _FrozenNeuron] = {}
        for seed, scale in seed_scales.items():
            s = int(seed)
            sc = float(scale)
            # Generate Raw Vector
            w = seeded_unit_vector(s, self.embedding_dim) * sc
            
            # IDRE v3: Fold In-Memory
            # W_fold = W_true @ P_fold
            if folding_matrix is not None:
                w = np.dot(w, folding_matrix)

            self._neurons[s] = _FrozenNeuron(weights=w.astype(np.float64), bias=self.bias)

    def has(self, seed: int) -> bool:
        return int(seed) in self._neurons

    def get(self, seed: int) -> _FrozenNeuron:
        return self._neurons[int(seed)]


class FieldBoundNode:
    def __init__(
        self,
        *,
        node_id: str,
        seed: int,
        anchor_seeds: Tuple[int, ...],
        anchor_weight: float,
        n_angles: int,
        scan_resolution: int,
        threshold: float,
        planes: int,
        tau_frac: float,
        print_deliveries: bool,
        print_events: bool,
        freeze_field: bool,
        backend: str,
        content_codec: str = "utf8",
        vocab: Optional[Vocab] = None,
        vocab_registry: Optional[Dict[bytes, Vocab]] = None,
        vocab_allow_literals: bool = True,
        max_plaintext_bytes: int = 65535,
        plasticity: bool = False,
        pepper: str = "",
    ):
        self.node_id = str(node_id)
        self.pepper = str(pepper)
        self.seed = int(seed)
        
        # IDRE v3: Initialize Topology Hiding (Unfolding Key)
        _dim = int(getattr(MTIConfig(), "embedding_dim", 64))
        self.topology = TopologyManager(seed=self.seed, dim=_dim)

        self.anchor_seeds = tuple(int(x) for x in anchor_seeds)
        self.anchor_weight = float(anchor_weight)
        self.n_angles = int(n_angles)
        self.scan_resolution = int(scan_resolution)
        self.threshold = float(threshold)
        self.planes = int(planes)
        self.tau_frac = float(tau_frac)
        self.print_deliveries = bool(print_deliveries)
        self.print_events = bool(print_events)
        self.freeze_field = bool(freeze_field)
        self.backend = str(backend).lower().strip()
        self.plasticity = bool(plasticity)
        self.max_payload_ints = int(DEFAULT_MAX_PAYLOAD_INTS)
        self.max_ct_len = int(DEFAULT_MAX_CT_LEN)
        self.max_plaintext_bytes = int(max_plaintext_bytes)
        
        # Offline Seed Ring (Ghost Recovery)
        self.offline_seed_ring: List[int] = []

        self.content_codec = str(content_codec).strip().lower()
        self.vocab = vocab
        self.vocab_registry = vocab_registry
        self.vocab_allow_literals = bool(vocab_allow_literals)
        
        # IDRE v3: Mandatory Vocab check based on user request
        if self.vocab is None:
             raise ValueError("IDRE v3 Compliance: 'vocab' argument is MANDATORY (Substrate Source).")

        if self.content_codec not in ("utf8", "vocab"):
            raise ValueError("bad_content_codec")
        if self.content_codec == "vocab" and (self.vocab is None or self.vocab_registry is None):
            raise ValueError("missing_vocab")

        self.config = MTIConfig()
        self.embedding_dim = int(getattr(self.config, "embedding_dim", 64))
        self.embedding_dim = int(getattr(self.config, "embedding_dim", 64))
        self._plane_list = derive_locked_planes(int(self.config.embedding_dim), self.planes)


        # Public compatibility profile
        self.field_profile: Dict[str, Any] = {
            "proto": "HIVE-P2P/1.2",
            "backend": str(self.backend),
            "freeze_field": bool(self.freeze_field),
            "embedding_dim": int(self.embedding_dim),
            "planes": int(self.planes),
            "tau_frac": float(self.tau_frac),
            "n_angles": int(self.n_angles),
            "scan_resolution": int(self.scan_resolution),
            "threshold": float(self.threshold),
            "anchor_weight": float(self.anchor_weight),
        }
        self.field_profile_id: str = compute_field_profile_id(self.field_profile)

        self.sessions: Dict[str, HiveSession] = {}
        self.pending_challenges: Dict[str, PendingChallenge] = {}
        self.max_pending_challenges = int(DEFAULT_MAX_PENDING_CHALLENGES)
        self._challenge_lock = threading.Lock()
        self._allowed_seeds = set([int(self.seed), *map(int, self.anchor_seeds)])
        self._cached_bits: Optional[List[int]] = None
        self._frozen: Optional[FrozenSubstrate] = None

        self.challenge_ttl_ms = int(DEFAULT_CHALLENGE_TTL_MS)
        self.skew_ms = int(DEFAULT_SKEW_MS)
        self.max_ttl_ms = int(DEFAULT_MAX_TTL_MS)
        self.default_ttl_ms = int(DEFAULT_DEFAULT_TTL_MS)

        if self.backend not in ("frozen", "lattice"):
            raise ValueError("backend must be 'frozen' or 'lattice'")

        if self.backend == "frozen":
            seed_scales: Dict[int, float] = {}
            for s in sorted(self._allowed_seeds):
                seed_scales[int(s)] = float(self.anchor_weight)
            # IDRE v3: Pass folding_matrix to secure the substrate in RAM
            self._frozen = FrozenSubstrate(
                embedding_dim=self.embedding_dim, 
                seed_scales=seed_scales, 
                bias=0.0,
                folding_matrix=self.topology.folding_matrix
            )
        else:
            try:
                from idre_clean.vendor.mti_evo.core.lattice import HolographicLattice
            except ImportError:
                try:
                    from vendor.mti_evo.core.lattice import HolographicLattice
                except ImportError:
                    from mti_evo.core.lattice import HolographicLattice

            self.lattice = HolographicLattice(config=self.config)
            for s in sorted(self._allowed_seeds):
                self._ensure_anchor(s)
                self._ensure_neuron(s)
            self._cached_bits = self._compute_fingerprint_bits(int(self.seed))

    def _ensure_neuron(self, seed: int):
        if self.backend == "frozen":
            if self.freeze_field and int(seed) not in self._allowed_seeds:
                raise ValueError("seed_not_allowed_in_frozen_field")
            return

        if not hasattr(self, "lattice"):
             raise AttributeError("self.lattice MISSING")

        if self.freeze_field and int(seed) not in self._allowed_seeds:
            raise ValueError("seed_not_allowed_in_frozen_field")
        if int(seed) in self.lattice.active_tissue:
            return
        x = np.zeros((int(self.config.embedding_dim),), dtype=np.float64)
        self.lattice.stimulate([int(seed)], input_signal=x, learn=False)

    def _ensure_anchor(self, seed: int):
        if int(seed) not in self.anchor_seeds:
            return
        if self.backend == "frozen":
            return

        self._ensure_neuron(seed)
        n = self.lattice.active_tissue[int(seed)]
        base = seeded_unit_vector(int(seed), int(self.config.embedding_dim))
        n.weights = base * float(self.anchor_weight)
        n.bias = 0.0

    def _tau_for_weights(self, weights: np.ndarray, *, plane_idx: int) -> float:
        ww = np.asarray(weights, dtype=np.float64).reshape(-1)
        u, w = self._plane_list[int(plane_idx)]
        a = float(np.dot(u, ww))
        b = float(np.dot(w, ww))
        amp = float(np.hypot(a, b))
        tau = amp * float(self.tau_frac)
        return float(max(tau, 1e-9))

    def _evolve_lattice(self, seed: int):
        """Execute plasticity update (stimulate & learn) for a seed."""
        if not self.plasticity:
            return
        
        # Anchor Check (Anchors reset anyway, but we still execute the learning step to match 'frozen' logic if needed? 
        # Actually anchors in 'frozen' don't evolve. In 'lattice', they reset then evolve.
        # So evolution on anchors is transient.
        # But for non-anchors, it's persistent.
        
        s = int(seed)
        if self.backend == "frozen":
             return

        # Ensure neuron exists before stimulating
        self._ensure_neuron(s)
        
        try:
            # print(f"[DEBUG] _evolve_lattice triggering for seed={s}")
            self.config.initial_lr = 5.0
            z = np.full((int(self.config.embedding_dim),), 0.05, dtype=np.float64)
            # pre_n = self.lattice.active_tissue[s]
            # res = pre_n.perceive(z)
            self.lattice.stimulate([s], input_signal=z, learn=True)
        except Exception as e:
            print(f"[ERROR] Plasticity update failed: {e}")
            raise e

    def _compute_fingerprint_bits(self, seed: int, mutate: bool = True) -> List[int]:
        s = int(seed)
        self._ensure_anchor(s)
        self._ensure_neuron(s)

        if self.backend == "frozen":
            assert self._frozen is not None
            if not self._frozen.has(s):
                raise ValueError("seed_not_initialized")
            n = self._frozen.get(s)
            weights = np.asarray(n.weights, dtype=np.float64).reshape(-1)
            bias = float(n.bias)
        else:
            # If backend=lattice, we read current state.
            # If mutate=True (Legacy/Aggressive), we evolve THEN read.
            # But for 'Verify-then-Mutate', we likely call with mutate=False (Read then External Evolve).
            # To preserve 'compatibility' with the old logic (Stimulate-then-Read) for unsuspecting callers:
            if mutate and self.plasticity:
                 # print(f"[DEBUG] Legacy Mutation in _compute_fingerprint_bits")
                 self._evolve_lattice(s)

            n = self.lattice.active_tissue[s]
            weights = np.asarray(n.weights, dtype=np.float64).reshape(-1)
            bias = float(getattr(n, "bias", 0.0))
            
            # IDRE v3: Lattice Backend Compatibility
            # The Lattice creates weights on-the-fly (Unfolded).
            # To match the V3 Protocol (which expects Folded Weights + Unfolding Key),
            # we must Fold them here so the Unfolding Key works.
            # This simulates "Homomorphic" operation.
            weights = self.topology.fold_substrate(weights)

        out: List[int] = []
        # IDRE v3: Get Unfolding Key
        unfolding_mtx = self.topology.unfolding_matrix
        
        for i, (u, w) in enumerate(self._plane_list):
            tau = self._tau_for_weights(weights, plane_idx=i) # Note: _tau_for_weights likely needs Unfolding too?
            # Actually _tau_for_weights uses .dot products.
            # If weights are Folded, we need to Unfold u,w inside _tau_for_weights too?
            # Yes. But _tau_for_weights definition (lines 231-238) isn't being modified here.
            # We should probably modify _tau_for_weights or doing the math inline.
            # Let's check _tau_for_weights content if possible.
            # Assuming _tau_for_weights takes (weights, plane_idx) and uses self._plane_list[plane_idx].
            # If so, it uses RAW planes.
            # So dot(u, w_folded) = GARBAGE.
            # We need to pass 'unfolding_matrix' to _tau_for_weights?
            # Or just calculate Tau here manually?
            # Let's calculate Tau here manually to be safe, overwriting the method call implies changing definition.
            # Wait, the original code called self._tau_for_weights.
            # Let's look at what I'm replacing:
            # tau = self._tau_for_weights(weights, plane_idx=i)
            
            # FIX: We need to calculate Tau using UNSCRAMBLED amplitude.
            # u_prime = u @ P_unfold
            # w_prime = u @ P_unfold
            # a = dot(u_prime, weights)
            # b = dot(w_prime, weights)
            
            u_prime = np.dot(u, unfolding_mtx)
            w_prime = np.dot(w, unfolding_mtx)
            
            a = float(np.dot(u_prime, weights))
            b = float(np.dot(w_prime, weights))
            amp = float(np.hypot(a, b))
            tau = float(max(amp * self.tau_frac, 1e-9))
            
            out.extend(
                scan_fingerprint_bits(
                    weights=weights,
                    bias=bias,
                    tau=float(tau),
                    u=u,
                    w=w,
                    n_angles=self.n_angles,
                    scan_resolution=self.scan_resolution,
                    threshold=self.threshold,
                    unfolding_matrix=unfolding_mtx
                )
            )
        return out

    def fingerprint_bits(self, seed: Optional[int] = None, mutate: bool = True, context_data: bytes = b"") -> List[int]:
        s = int(self.seed if seed is None else seed)
        # Note: If context_data is provided, we can't use the generic cached bits because cache is context-agnostic.
        # But wait, self._cached_bits is usually for the Identity (Root Seed).
        # Identity is usually context-free?
        # User wants: HMAC(pepper, domain_tag || session_id || raw_bits)
        # If we are doing Identity Proof, session_id is relevant.
        # So we should probably invalidate/ignore cache if context_data is present.
        
        if self.freeze_field and self._cached_bits is not None and s == int(self.seed) and not context_data:
            # Cached bits are ALREADY flavored if we computed them correctly (without context).
            return list(self._cached_bits)
        
        bits = self._compute_fingerprint_bits(s, mutate=mutate)
        
        # Apply Pepper (Defense in Depth)
        if self.pepper:
             # Bits -> Bytes
             bits_bytes = bytes(int(b) & 1 for b in bits)
             
             # Domain Separation
             # "IDRE-PEPPER-v1" || context_data || bits
             domain = b"IDRE-PEPPER-v1"
             msg = domain + context_data + bits_bytes
             
             # Expand back to list of ints (0/1)
             n_bits = len(bits)
             derived_bits = []
             counter = 0
             
             while len(derived_bits) < n_bits:
                  h_chunk = hmac.new(self.pepper.encode("utf-8"), msg + counter.to_bytes(4, "big"), hashlib.sha256).digest()
                  for b in h_chunk:
                       for i in range(8):
                            derived_bits.append((b >> i) & 1)
                  counter += 1
             bits = derived_bits[:n_bits]
        
        if self.freeze_field and s == int(self.seed) and not context_data:
            self._cached_bits = list(bits)
        return bits

    def _cleanup_challenges(self, *, now_ms: int) -> None:
        dead = []
        for pid, rec in self.pending_challenges.items():
            if bool(rec.used) or int(now_ms) > int(rec.expires_at_ms):
                dead.append(pid)
        for pid in dead:
            self.pending_challenges.pop(pid, None)

    def issue_challenge(self, peer_id: str) -> PendingChallenge:
        pid = str(peer_id)
        ch = secrets.token_hex(16)
        n_ms = int(_now_ms())
        rec = PendingChallenge(
            challenge=str(ch),
            issued_at_ms=int(n_ms),
            expires_at_ms=int(n_ms) + int(self.challenge_ttl_ms),
            used=False,
        )
        with self._challenge_lock:
            self._cleanup_challenges(now_ms=n_ms)
            if pid not in self.pending_challenges and len(self.pending_challenges) >= int(self.max_pending_challenges):
                oldest_pid = None
                oldest_t = None
                for k, v in self.pending_challenges.items():
                    t = int(getattr(v, "issued_at_ms", 0))
                    if oldest_t is None or t < int(oldest_t):
                        oldest_t = t
                        oldest_pid = k
                if oldest_pid is not None:
                    self.pending_challenges.pop(str(oldest_pid), None)
            self.pending_challenges[pid] = rec
        return rec

    def consume_challenge(self, peer_id: str, challenge: str) -> bool:
        pid = str(peer_id)
        n_ms = int(_now_ms())
        with self._challenge_lock:
            self._cleanup_challenges(now_ms=n_ms)
            rec = self.pending_challenges.get(pid)
            if rec is None:
                return False
            if bool(rec.used):
                self.pending_challenges.pop(pid, None)
                return False
            if int(n_ms) > int(rec.expires_at_ms):
                self.pending_challenges.pop(pid, None)
                return False
            if str(challenge) != str(rec.challenge):
                self.pending_challenges.pop(pid, None)
                return False
            rec.used = True
            self.pending_challenges.pop(pid, None)
            return True



    def encrypt_message(
        self,
        message: str,
        *,
        session_id: str,
        nonce: int,
        ephemeral_salt: int,
        pad_bytes: int = 0,
        aad: bytes = b"",
        codec: Optional[NeuralCodec] = None,
        injected_packets: List[bytes] = [],
        ratchet_key: Optional[int] = None,
    ) -> Tuple[List[int], bytes]:
        if self.config and getattr(self, "content_codec", "utf8") == "vocab" and self.vocab:
            # User optimization: Use Tokenizer (Vocab) instead of raw UTF-8
            blob = vocab_encode_text(
                message, 
                self.vocab, 
                allow_literals=bool(getattr(self, "vocab_allow_literals", True))
            )
        else:
            blob = pack_plaintext(message)

        return self.encrypt_bytes(
            bytes(blob),
            session_id=session_id,
            nonce=int(nonce),
            ephemeral_salt=int(ephemeral_salt),
            pad_bytes=int(pad_bytes),
            aad=aad,
            codec=codec,
            injected_packets=injected_packets,
            ratchet_key=ratchet_key,
        )

    def encrypt_bytes(
        self,
        plaintext: bytes,
        *,
        session_id: str,
        nonce: int,
        ephemeral_salt: int,
        pad_bytes: int = 0,
        aad: bytes = b"",
        codec: Optional[NeuralCodec] = None,
        injected_packets: List[bytes] = [],
        ratchet_key: Optional[int] = None,
    ) -> Tuple[List[int], bytes]:
        from .crypto import encrypt_stream as _encrypt_stream
        
        # Retrieve state (bits)
        # Ouroboros: Use provided Ratchet Key (KDF), else Root Seed (Field)
        if ratchet_key is not None:
             bits = self._derive_ratchet_bits(int(ratchet_key))
             # No field evolution for ratchet keys (they are purely mathematical)
        else:
             bits = self.fingerprint_bits(self.seed, mutate=False, context_data=session_id.encode())
        
        # Encrypt
        ct_ints = _encrypt_stream(
            plaintext,
            bits=bits,
            session_id=session_id,
            nonce=nonce,
            ephemeral_salt=ephemeral_salt,
            pad_bytes=0,
            max_bytes=int(self.max_plaintext_bytes),
            codec=codec,
            injected_packets=injected_packets            
        )
        
        # Calculate MAC Key
        key = derive_mac_key(
            bits=bits,
            session_id=session_id,
            nonce=nonce,
            ephemeral_salt=ephemeral_salt
        )
        # State Evolution
        # Always evolve to maintain Substrate Plasticity (Anti-Replay)
        self._evolve_lattice(self.seed)
        
        # Tag
        tag = hmac.new(key, (aad or b"") + bytes(int(x) & 0xFF for x in ct_ints), hashlib.sha256).digest()
        
        # Frame
        return frame_payload(ct_ints, tag, pad_bytes=pad_bytes), tag

    def decrypt_message(
        self,
        payload: List[int],
        *,
        session_id: str,
        nonce: int,
        ephemeral_salt: int,
        aad: bytes = b"",
        codec: Optional[NeuralCodec] = None,
        ratchet_key: Optional[int] = None,
    ) -> Tuple[bool, str, List[bytes], bytes]:
        # wrapper for decrypt_bytes
        blob, reason, acks, tag = self.decrypt_bytes(
            payload, 
            session_id=session_id, 
            nonce=nonce, 
            ephemeral_salt=ephemeral_salt, 
            aad=aad,
            codec=codec,
            ratchet_key=ratchet_key,
        )
        if blob is None:
            return False, reason, [], b""
        try:
             ok, res = unpack_plaintext(bytes(blob))
             if not ok:
                 return False, "unpack_error", [], tag
             return True, res, acks, tag
        except:
             return False, "unpack_error_ex", [], tag

    def decrypt_bytes(
        self,
        payload: List[int],
        *,
        session_id: str,
        nonce: int,
        ephemeral_salt: int,
        aad: bytes = b"",
        codec: Optional[NeuralCodec] = None,
        ratchet_key: Optional[int] = None,
    ) -> Tuple[Optional[bytes], str, List[bytes], bytes]:
        from .crypto import decrypt_stream as _decrypt_stream
        
        if len(payload) < 1 + 8 + 8 + 32: # header + mac
             return None, "payload_too_short", [], b""
        
        # Extract fields
        try:
            ct, tag_from_frame = unframe_payload(payload, max_ct_len=self.max_ct_len)
        except Exception:
            return None, "framing_error", [], b""

        if not ct or len(tag_from_frame) != MAC_LEN:
             return None, "framing_error_empty", [], b""

        # Retrieve state (bits)
        # Ouroboros: Use Ratchet Key if available
        if ratchet_key is not None:
             bits = self._derive_ratchet_bits(int(ratchet_key))
        else:
             bits = self.fingerprint_bits(self.seed, mutate=False, context_data=session_id.encode())
        
        # Verify MAC
        key = derive_mac_key(
            bits=bits, 
            session_id=session_id, 
            nonce=nonce, 
            ephemeral_salt=ephemeral_salt
        )
        
        exp = hmac.new(key, (aad or b"") + bytes(int(x) & 0xFF for x in ct), hashlib.sha256).digest()
        
        if not hmac.compare_digest(exp, tag_from_frame):
             # DO NOT EVOLVE ON MAC FAILURE
             return None, "mac_mismatch", [], tag_from_frame
             
        # MAC Verified: Now Commit Evolved State
        # Always evolve to maintain Substrate Plasticity
        self._evolve_lattice(self.seed)
        
        # Decrypt Stream
        pt, reason, acks = _decrypt_stream(
            ct,
            bits=bits,
            session_id=session_id,
            nonce=nonce,
            ephemeral_salt=ephemeral_salt,
            codec=codec
        )
        return pt, "ok", acks, tag_from_frame

    def create_verify_req(self, session_id: str, ephemeral_salt: int, challenge: str) -> Dict[str, Any]:
        nonce = secrets.randbits(64)
        aad = canonical_json(
            {
                "type": "VERIFY_REQ",
                "field_profile_id": str(getattr(self, "field_profile_id", "")),
                "challenge": str(challenge),
                "session_id": str(session_id),
                "nonce": int(nonce),
                "ephemeral_salt": int(ephemeral_salt),
            }
        )
        payload, _ = self.encrypt_message(
            RESONANT_SIGNATURE,
            session_id=str(session_id),
            nonce=int(nonce),
            ephemeral_salt=int(ephemeral_salt),
            pad_bytes=0,
            aad=aad,
        )
        if self.print_events:
            print(f"[{self.node_id}] VERIFY_REQ create session={str(session_id)[:8]}.. nonce={nonce}")
        return {
            "type": "VERIFY_REQ",
            "field_profile_id": str(getattr(self, "field_profile_id", "")),
            "challenge": str(challenge),
            "session_id": str(session_id),
            "nonce": int(nonce),
            "ephemeral_salt": int(ephemeral_salt),
            "payload": payload,
        }

    def process_verify_req(self, msg: Dict[str, Any], peer_id: str, ttl_s: float = 600.0) -> bool:
        if peer_id not in self.pending_challenges:
            if self.print_events:
                print(f"[{self.node_id}] VERIFY_REQ reject peer={peer_id} (no_pending_challenge)")
            return False

        rec = self.pending_challenges[peer_id]
        challenge_str = rec.challenge
        
        payload_list = msg.get("payload")
        if not isinstance(payload_list, list):
            if self.print_events:
                print(f"[{self.node_id}] VERIFY_REQ reject peer={peer_id} (bad_payload_type)")
            return False

        e_salt = int(msg.get("ephemeral_salt", 0))
        sess_id = str(msg.get("session_id", ""))
        nonce = int(msg.get("nonce", 0))
        
        aad = canonical_json(
            {
                "type": "VERIFY_REQ",
                "field_profile_id": str(getattr(self, "field_profile_id", "")),
                "challenge": str(challenge_str),
                "session_id": str(sess_id),
                "nonce": int(nonce),
                "ephemeral_salt": int(e_salt),
            }
        )

        valid, text, _, _ = self.decrypt_message(
            payload_list,
            session_id=sess_id,
            nonce=nonce,
            ephemeral_salt=e_salt,
            aad=aad
        )
        
        if not valid or text != RESONANT_SIGNATURE:
            if self.print_events:
                reason = text if not valid else "bad_sig"
                print(f"[{self.node_id}] VERIFY_REQ reject peer={peer_id} reason={reason}")
            return False

        # Epoch Anchor: Initialize rolling chain hash
        # Genesis Hash = HMAC(seed, "GENESIS:" + sess_id)
        # Both sides start with same genesis hash for out/in sequences.
        genesis_key = hmac.new(str(self.seed).encode(), f"GENESIS:{sess_id}".encode(), hashlib.sha256).digest()
        
        # Neural Codec Init
        codec_key = hmac.new(str(self.seed).encode(), f"CODEC:{sess_id}".encode(), hashlib.sha256).digest()
        codec = NeuralCodec(codec_key, role="responder")
        
        # Ouroboros: Initialize Ratchet Key from Root Seed + Session ID
        ratchet_key = self._kdf(self.seed, f"INIT::{sess_id}")

        self.sessions[peer_id] = HiveSession(
            session_id=sess_id,
            peer_id=peer_id,
            start_time=time.time(),
            ttl_s=float(msg.get("ttl_s", ttl_s)),
            ephemeral_salt=e_salt,
            chain_hash=genesis_key,
            out_seq=1,
            in_seq=1,
            codec=codec,
            ratchet_key=ratchet_key
        )
        if self.print_events:
            print(f"[{self.node_id}] SESSION ESTABLISHED with {peer_id} (sid={sess_id})")
        
        del self.pending_challenges[peer_id]
        return True

    def force_session(self, peer_id: str, session_id: str, ephemeral_salt: int):
        # Epoch Anchor: Initialize rolling chain hash
        genesis_input = f"{self.seed}:{session_id}:GENESIS".encode("utf-8")
        chain_hash = hashlib.sha256(genesis_input).digest()
        
        # Neural Codec Init
        codec_key = hmac.new(str(self.seed).encode(), f"CODEC:{session_id}".encode(), hashlib.sha256).digest()
        codec = NeuralCodec(codec_key, role="forced")

        # Ouroboros: Initialize Ratchet Key
        ratchet_key = self._kdf(self.seed, f"INIT::{session_id}")

        self.sessions[peer_id] = HiveSession(
            session_id=session_id,
            peer_id=str(peer_id),
            start_time=time.time(),
            ttl_s=3600.0,
            ephemeral_salt=ephemeral_salt,
            chain_hash=chain_hash,
            codec=codec,
            ratchet_key=ratchet_key
        )
        if self.print_events:
            print(f"[{self.node_id}] SESSION FORCED with {peer_id} (sid={session_id})")

    def rollback_anchor(self, peer_id: str) -> bool:
        """Rollback Epoch Anchor to previous state if delivery failed."""
        dst = str(peer_id)
        if dst not in self.sessions:
             return False
        sess = self.sessions[dst]
        if not sess.prev_chain_hash:
             return False
        sess.chain_hash = sess.prev_chain_hash
        sess.prev_chain_hash = b""
        if self.print_events:
             print(f"[{self.node_id}] ROLLBACK ANCHOR peer={dst}")
        return True

    def _kdf(self, input_key: int, data: str) -> int:
        """Key Derivation Function: HMAC-SHA256(Key, Data) -> Int"""
        key_bytes = str(input_key).encode()
        data_bytes = data.encode()
        digest = hmac.new(key_bytes, data_bytes, hashlib.sha256).hexdigest()
        return int(digest, 16)

    def _derive_ratchet_bits(self, ratchet_key: int) -> List[int]:
        """
        Derive pseudo-random bits from a Ratchet Key for transport encryption.
        This bypasses the Neural Field (which is likely frozen/static) and uses
        standard crypto primitives to generate the keystream bits, ensuring
        Forward Secrecy without requiring lattice plasticity.
        """
        # 1. Determine target length from Root Seed bits
        if self._cached_bits is None:
             self._cached_bits = self._compute_fingerprint_bits(self.seed, mutate=False)
        target_len = len(self._cached_bits)
        
        # 2. Expand Ratchet Key into bits
        # We need target_len bits (0 or 1)
        # We use HKDF-like expansion using HMAC-SHA256
        out = []
        counter = 0
        key_bytes = str(ratchet_key).encode()
        
        while len(out) < target_len:
             # Hash(Key + Counter)
             block = hmac.new(key_bytes, counter.to_bytes(4, 'big'), hashlib.sha256).digest()
             # Convert bytes to bits
             for b in block:
                  for i in range(8):
                       if len(out) >= target_len: break
                       out.append((b >> i) & 1)
             counter += 1
        return out

    def ingest_finalized_block(self, block_hash: str):
        """
        The Ouroboros Trigger.
        Called when the Substrate Light Client confirms a new finalized block.
        Rotates ALL session keys forward. Forward Secrecy is immediate.
        """
        if self.print_events:
            print(f"[*] Ouroboros: Ingesting Reality {block_hash[:8]}...")
        
        for sess_id, sess in self.sessions.items():
            if sess.ratchet_key is None:
                continue # Skip legacy sessions
            
            # 1. Evolve the Key
            # Next_Key = HMAC(Current_Key, Block_Hash || Pepper)
            old_key_fragment = str(sess.ratchet_key)[:8]
            
            mix_data = str(block_hash)
            if self.pepper:
                mix_data += f":{self.pepper}"
            
            sess.ratchet_key = self._kdf(sess.ratchet_key, mix_data)
            
            # 2. Update Metadata
            sess.last_ratchet_hash = block_hash
            
            if self.print_events:
                print(f"    [>] Session {sess_id[:6]}: Ratcheted {old_key_fragment}... -> {str(sess.ratchet_key)[:8]}...")

    def send(
        self,
        dst_node_id: str,
        content: str,
        pad_bytes: int = 0,
        *,
        override_created_at_ms: Optional[int] = None,
        override_expires_at_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        dst = str(dst_node_id)
        if dst not in self.sessions:
            if self.print_events:
                print(f"[{self.node_id}] SEND blocked dst={dst} (no_session)")
            return {}
        sess = self.sessions[dst]
        if not sess.is_valid():
            if self.print_events:
                print(f"[{self.node_id}] SEND blocked dst={dst} (session_expired)")
            return {}

        nonce = secrets.randbits(64)
        while nonce in sess.seen._set:
            nonce = secrets.randbits(64)

        if override_created_at_ms is not None:
            created_at_ms = int(override_created_at_ms)
        else:
            created_at_ms = _now_ms()

        if override_expires_at_ms is not None:
            expires_at_ms = int(override_expires_at_ms)
        else:
            expires_at_ms = int(created_at_ms) + int(self.default_ttl_ms)

        header = {
            "type": "DATA",
            "field_profile_id": str(getattr(self, "field_profile_id", "")),
            "session_id": sess.session_id,
            "nonce": int(nonce),
            "created_at_ms": int(created_at_ms),
            "expires_at_ms": int(expires_at_ms),
            "src_node_id": self.node_id,
            "dst_node_id": dst,
            "hop_count": 0,
            "max_hops": 8,
        }
        aad = canonical_json(header)
        sess.out_seq += 1
        # Epoch Anchor: Bind to rolling chain hash AND Sequence Number
        aad_with_anchor = aad + sess.chain_hash + struct.pack(">Q", sess.out_seq)

        # Piggyback ACKs (Neural Codec)
        acks = []
        if sess.pending_acks:
            acks = list(sess.pending_acks)
            sess.pending_acks.clear()

        try:
            if self.content_codec == "utf8":
                payload, tag = self.encrypt_message(
                    content,
                    session_id=sess.session_id,
                    nonce=int(nonce),
                    ephemeral_salt=int(sess.ephemeral_salt),
                    pad_bytes=int(pad_bytes),
                    aad=aad_with_anchor,
                    codec=sess.codec,
                    injected_packets=acks,
                    ratchet_key=sess.ratchet_key,
                )
            else:
                assert self.vocab is not None
                blob = vocab_encode_text(str(content), self.vocab, allow_literals=bool(self.vocab_allow_literals))
                payload, tag = self.encrypt_bytes(
                    blob,
                    session_id=sess.session_id,
                    nonce=int(nonce),
                    ephemeral_salt=int(sess.ephemeral_salt),
                    pad_bytes=int(pad_bytes),
                    aad=aad_with_anchor,
                    codec=sess.codec,
                    injected_packets=acks,
                    ratchet_key=sess.ratchet_key,
                )
            
            # Epoch Anchor: Update rolling chain hash (with rollback support)
            payload_bytes = bytes(payload)
            sess.prev_chain_hash = sess.chain_hash
            sess.chain_hash = hashlib.sha256(sess.chain_hash + payload_bytes).digest()

        except Exception as e:
            # Revert sequence on failure to ensure next try matches
            sess.out_seq -= 1
            if self.print_events:
                 print(f"[{self.node_id}] SEND blocked dst={dst} ({repr(e)})")
            return {}

        if self.print_events:
            plen = len(payload) if isinstance(payload, list) else -1
            print(f"[{self.node_id}] SENT dst={dst} nonce={nonce} payload_len={plen} seq={sess.out_seq}")
        header["payload"] = payload
        return header

    def receive(self, msg: Dict[str, Any], prev_hop_id: str) -> Dict[str, Any]:
        prev = str(prev_hop_id)
        if prev not in self.sessions:
            if self.print_events:
                print(f"[{self.node_id}] RECV reject from={prev} reason=unknown_session")
            return {"status": "reject", "reason": "unknown_session"}

        if str(msg.get("field_profile_id", "")) != str(getattr(self, "field_profile_id", "")):
            if self.print_events:
                print(f"[{self.node_id}] RECV reject from={prev} reason=wrong_profile")
            return {"status": "reject", "reason": "wrong_profile"}

        sess = self.sessions[prev]
        if not sess.is_valid() or str(msg.get("session_id")) != sess.session_id:
            if self.print_events:
                print(f"[{self.node_id}] RECV reject from={prev} reason=invalid_session")
            return {"status": "reject", "reason": "invalid_session"}

        nonce = int(msg.get("nonce", 0))
        
        # PLASTICITY PROTECTION: Check Replay BEFORE Decrypt/Evolve
        if nonce in sess.seen._set:
            if self.print_events:
                print(f"[{self.node_id}] RECV reject from={prev} reason=replay nonce={nonce}")
            return {"status": "reject", "reason": "replay"}
            
        created_at_ms = int(msg.get("created_at_ms", 0) or 0)
        expires_at_ms = int(msg.get("expires_at_ms", 0) or 0)
        if created_at_ms <= 0 or expires_at_ms <= 0:
            if self.print_events:
                print(f"[{self.node_id}] RECV reject from={prev} reason=bad_time")
            return {"status": "reject", "reason": "bad_time"}
        now_ms = _now_ms()
        if now_ms > int(expires_at_ms):
            if self.print_events:
                print(f"[{self.node_id}] RECV reject from={prev} reason=expired")
            return {"status": "reject", "reason": "expired"}
        if int(created_at_ms) > int(now_ms) + int(self.skew_ms):
            if self.print_events:
                print(f"[{self.node_id}] RECV reject from={prev} reason=clock_skew")
            return {"status": "reject", "reason": "clock_skew"}
        if int(expires_at_ms) - int(created_at_ms) > int(self.max_ttl_ms):
            if self.print_events:
                print(f"[{self.node_id}] RECV reject from={prev} reason=ttl_too_long")
            return {"status": "reject", "reason": "ttl_too_long"}

        payload = msg.get("payload")
        if not isinstance(payload, list):
            if self.print_events:
                print(f"[{self.node_id}] RECV reject from={prev} reason=bad_payload")
            return {"status": "reject", "reason": "bad_payload"}

        header = {
            "type": str(msg.get("type", "")),
            "field_profile_id": str(msg.get("field_profile_id", "")),
            "session_id": str(msg.get("session_id", "")),
            "nonce": int(msg.get("nonce", 0)),
            "created_at_ms": int(created_at_ms),
            "expires_at_ms": int(expires_at_ms),
            "src_node_id": str(msg.get("src_node_id", "")),
            "dst_node_id": str(msg.get("dst_node_id", "")),
            "hop_count": int(msg.get("hop_count", 0)),
            "max_hops": int(msg.get("max_hops", 0)),
        }
        aad = canonical_json(header)
        # Epoch Anchor: Bind to Consensus Reality (Block Hash) AND Sequence Number
        # SLIDING WINDOW (W=5)
        window_size = 5
        valid_decrypt = False
        blob_found = None
        tag_found = b""
        seq_found = -1
        
        base_seq = sess.in_seq + 1
        
        for offset in range(window_size + 1):
            candidate_seq = base_seq + offset
            aad_check = aad + sess.chain_hash + struct.pack(">Q", candidate_seq)
            
            blob_opt, reason_opt, acks_opt, tag_opt = self.decrypt_bytes(
                payload, session_id=sess.session_id, nonce=nonce, ephemeral_salt=sess.ephemeral_salt, 
                aad=aad_check, codec=sess.codec, ratchet_key=sess.ratchet_key
            )
            
            if blob_opt is not None:
                valid_decrypt = True
                blob_found = blob_opt
                seq_found = candidate_seq
                if acks_opt:
                    sess.pending_acks.extend(acks_opt)
                break
        
        if not valid_decrypt:
             if self.print_events:
                 print(f"[{self.node_id}] RECV reject from={prev} reason=mac_mismatch (window={window_size})")
             return {"status": "reject", "reason": "mac_mismatch"}

        # Update State (Gap Detection)
        if seq_found != base_seq:
            if self.print_events:
                print(f"[{self.node_id}] RESILIENCE: Gap Detected! Jumped {sess.in_seq} -> {seq_found} (Missed {seq_found - sess.in_seq - 1})")
        
        sess.in_seq = seq_found
        sess.chain_hash = hashlib.sha256(sess.chain_hash + bytes(payload)).digest()

        # Decode Content
        if self.content_codec == "utf8":
            try:
                ok, text = unpack_plaintext(bytes(blob_found))
                if not ok:
                     if self.print_events:
                         print(f"[{self.node_id}] RECV reject from={prev} reason=unpack_error")
                     return {"status": "reject", "reason": "unpack_error"}
            except:
                 if self.print_events:
                     print(f"[{self.node_id}] RECV reject from={prev} reason=unpack_error_ex")
                 return {"status": "reject", "reason": "unpack_error_ex"}
                 
        else: # Vocab Path
            ok_id, _reason_id, vid = vocab_peek_vocab_id(blob_found)
            if not ok_id:
                if self.print_events:
                    print(f"[{self.node_id}] RECV reject from={prev} reason=bad_plaintext")
                return {"status": "reject", "reason": "bad_plaintext"}
            
            assert self.vocab_registry is not None
            v = self.vocab_registry.get(bytes(vid))
            if v is None:
                if self.print_events:
                    print(f"[{self.node_id}] RECV reject from={prev} reason=wrong_vocab")
                return {"status": "reject", "reason": "wrong_vocab"}
            
            ok2, reason2, text = vocab_decode_text(blob_found, v, allow_literals=bool(self.vocab_allow_literals))
            if not ok2:
                if self.print_events:
                    print(f"[{self.node_id}] RECV reject from={prev} reason={reason2}")
                return {"status": "reject", "reason": reason2}

        # Success! Commit Nonce and Sequence
        # sess.in_seq already updated above (Gap Detection logic)
        sess.seen.check_and_add(nonce)

        if str(msg.get("dst_node_id")) == self.node_id:
            if self.print_deliveries:
                print(f"[DELIVERED to {self.node_id} from {prev}] {text}")
            return {"status": "delivered"}
        
        msg_dst = str(msg.get("dst_node_id"))
        if self.print_events:
            print(f"[{self.node_id}] RECV reject from={prev} reason=no_forward dst={msg_dst}")
        return {"status": "reject", "reason": "no_forward"}

    def ingest_offline_envelope(self, blob: bytes) -> Tuple[bool, str, Optional[str]]:
        if not self.offline_seed_ring:
            return False, "no_ring", None

        for seed_candidate in self.offline_seed_ring:
            try:
                bits = compute_fingerprint_bits_frozen_v12(
                    seed=int(seed_candidate),
                    embedding_dim=int(self.embedding_dim),
                    planes=int(self.planes),
                    tau_frac=float(self.tau_frac),
                    n_angles=int(self.n_angles),
                    scan_resolution=int(self.scan_resolution),
                    threshold=float(self.threshold),
                    anchor_weight=float(self.anchor_weight),
                )
                
                ok, reason, hdr, pt = open_envelope(
                    bits=bits,
                    blob=blob,
                    expected_field_profile_id=self.field_profile_id,
                    enforce_time=True,
                    skew_ms=self.skew_ms
                )
                
                if ok:
                    assert pt is not None
                    if self.print_events:
                        print(f"[{self.node_id}] OFFLINE_RECOVER seed={seed_candidate} profile={self.field_profile_id}")
                    
                    try:
                        text = pt.decode("utf-8")
                        if self.print_deliveries:
                            print(f"[OFFLINE RECOVERED] {text}")
                        return True, "ok", text
                    except Exception:
                        return True, "ok_binary", pt.hex()

            except Exception:
                continue
        
        return False, "decrypt_failed", None
