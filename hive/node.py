import hashlib
import hmac
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

# Prefer vendored minimal MTI-EVO config
try:
    from vendor.mti_evo.core.config import MTIConfig  # type: ignore
except Exception:
    from mti_evo.core.config import MTIConfig  # type: ignore

from core.frozen_physics import compute_fingerprint_bits_frozen_v12
from core.offline_envelope import open_envelope
from core.vocab_codec import (
    Vocab,
    decode_text as vocab_decode_text,
    encode_text as vocab_encode_text,
    peek_vocab_id as vocab_peek_vocab_id,
)

from .utils import (
    canonical_json,
    compute_field_profile_id,
    _now_ms,
    frame_payload, unframe_payload, 
    pack_plaintext, unpack_plaintext, DEFAULT_MAX_CT_LEN, RESONANT_SIGNATURE,
    DEFAULT_MAX_PAYLOAD_INTS,
    DEFAULT_CHALLENGE_TTL_MS, DEFAULT_SKEW_MS, 
    DEFAULT_MAX_TTL_MS, DEFAULT_DEFAULT_TTL_MS, 
    DEFAULT_MAX_PENDING_CHALLENGES
)
try:
    from core.physics_v12 import (
        derive_locked_planes,
        scan_fingerprint_bits,
        seeded_unit_vector,
    )
except Exception:
    from core.physics_v12 import (
        derive_locked_planes,
        scan_fingerprint_bits,
        seeded_unit_vector,
    )
from .topology import TopologyManager
from .substrate import FrozenSubstrate
from .challenges import ChallengeStore
from .protocol import (
    aad_with_epoch_anchor,
    codec_session_key,
    forced_chain_hash,
    genesis_chain_hash,
    update_chain_hash,
    verify_req_aad,
)
from .ratchet import derive_ratchet_bits, kdf_int
try:
    from core.session import HiveSession, PendingChallenge
except Exception:
    from core.session import HiveSession, PendingChallenge
from core.neural_codec import NeuralCodec
from .crypto import derive_mac_key

from functools import wraps
import threading

def _with_lock(method):
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapper


class FieldBoundNode:
    """
    Core IDRE Protocol Node.
    
    Handles sessions, neural encoding/decoding, cryptography, replay protection,
    and sending/receiving IDRE-compliant packets.
    """
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
        topology_seed: Optional[int] = None,
        healing_mode: str = "none",
    ):
        """Initializes a new FieldBoundNode with specific physical and cryptographic parameters."""
        self.node_id = str(node_id)
        self.pepper = str(pepper)
        self.seed = int(seed)
        self._lock = threading.RLock()
        
        # IDRE v2.4: Pepper is MANDATORY for production deployments.
        if not self.pepper:
            raise ValueError("IDRE SECURITY VIOLATION: 'pepper' is mandatory. Without pepper, fingerprint bits are vulnerable to gradient-descent weight recovery.")
        
        # IDRE v3: Initialize Topology Hiding (Unfolding Key)
        _dim = int(getattr(MTIConfig(), "embedding_dim", 64))
        self.topology = TopologyManager(seed=int(topology_seed) if topology_seed is not None else self.seed, dim=_dim)

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

        # REFACTORED: Resonant Multiverse Support
        # self.timelines: PeerID -> List[HiveSession]
        # We limit the number of active forks to avoid explosion.
        self.timelines: Dict[str, List[HiveSession]] = {}
        
        # Healing Mode: "none" (Die), "multiverse" (Fork)
        # We default to "none" for strict security.
        self.healing_mode = healing_mode
        
        self._challenges = ChallengeStore()
        self.pending_challenges: Dict[str, PendingChallenge] = self._challenges.pending
        self.max_pending_challenges = int(DEFAULT_MAX_PENDING_CHALLENGES)
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
            # Keep cache canonical: context-free fingerprint_bits() applies pepper policy.
            self._cached_bits = self.fingerprint_bits(int(self.seed), mutate=False)

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
        
        # Evolution on anchors is transient, but persistent for non-anchors.
        
        s = int(seed)
        if self.backend == "frozen":
             return

        # Ensure neuron exists before stimulating
        self._ensure_neuron(s)
        
        try:
            # logger.info(f"[DEBUG] _evolve_lattice triggering for seed={s}")
            self.config.initial_lr = 5.0
            z = np.full((int(self.config.embedding_dim),), 0.05, dtype=np.float64)
            # pre_n = self.lattice.active_tissue[s]
            # res = pre_n.perceive(z)
            self.lattice.stimulate([s], input_signal=z, learn=True)
        except Exception as e:
            logger.error(f"Plasticity update failed: {e}")
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
            # Preserve compatibility with legacy Stimulate-then-Read logic
            if mutate and self.plasticity:
                 # logger.info(f"[DEBUG] Legacy Mutation in _compute_fingerprint_bits")
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
            # Calculate Tau using unscrambled amplitude.
            
            u_prime = np.dot(u, unfolding_mtx)
            w_prime = np.dot(w, unfolding_mtx)
            
            a = np.dot(u_prime, weights)
            b = np.dot(w_prime, weights)
            amp = abs(int(a)) + abs(int(b))
            tau = max(int(amp * self.tau_frac), 1)
            
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
        # If context_data is provided, cache should be invalidated or ignored
        # because the generic cached bits are context-agnostic.
        
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

    def issue_challenge(self, peer_id: str) -> PendingChallenge:
        return self._challenges.issue(
            peer_id=str(peer_id),
            ttl_ms=int(self.challenge_ttl_ms),
            max_pending=int(self.max_pending_challenges),
        )

    def consume_challenge(self, peer_id: str, challenge: str) -> bool:
        return bool(self._challenges.consume(str(peer_id), str(challenge)))



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
        injected_packets: Optional[List[bytes]] = None,
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
            injected_packets=list(injected_packets or []),
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
        injected_packets: Optional[List[bytes]] = None,
        ratchet_key: Optional[int] = None,
    ) -> Tuple[List[int], bytes]:
        from .crypto import encrypt_stream as _encrypt_stream
        
        # Retrieve state (bits)
        # Ouroboros: Use provided Ratchet Key (KDF), else Root Seed (Field)
        if ratchet_key is not None:
            if self._cached_bits is None:
                # Canonical cache must include pepper when configured.
                self._cached_bits = self.fingerprint_bits(self.seed, mutate=False)
            bits = derive_ratchet_bits(int(ratchet_key), len(self._cached_bits))
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
            pad_bytes=512,  # IDRE V2: Enforce constant-size cell framing
            max_bytes=int(self.max_plaintext_bytes),
            codec=codec,
            injected_packets=list(injected_packets or [])
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
        
        # ---------------------------------------------------------
        # IDRE V2 Traffic Analysis Mitigation: Strict Constant-Size Cells
        MAC_LEN = 32
        # Wire Format: len(n_bytes) + len(ct_ints) + MAC_LEN = 4 + len(ct_ints) + 32
        base_len = 4 + len(ct_ints) + MAC_LEN
        
        target_cell_size = self.max_payload_ints  # e.g., 512
        if base_len > target_cell_size:
             raise ValueError("Payload exceeds strict constant-size cell limit.")
             
        total_pad = target_cell_size - base_len

        # Frame
        return frame_payload(ct_ints, tag, pad_bytes=total_pad), tag

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
        
        MAC_LEN = 32
        if len(payload) < 1 + MAC_LEN:
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
            if self._cached_bits is None:
                # Canonical cache must include pepper when configured.
                self._cached_bits = self.fingerprint_bits(self.seed, mutate=False)
            bits = derive_ratchet_bits(int(ratchet_key), len(self._cached_bits))
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
        hdr, aad = verify_req_aad(
            field_profile_id=str(getattr(self, "field_profile_id", "")),
            challenge=str(challenge),
            session_id=str(session_id),
            nonce=int(nonce),
            ephemeral_salt=int(ephemeral_salt),
        )
        # Handshake payload must stay stable regardless of content codec (utf8 vs vocab).
        # The verify path expects `pack_plaintext` framing.
        payload, _ = self.encrypt_bytes(
            pack_plaintext(RESONANT_SIGNATURE),
            session_id=str(session_id),
            nonce=int(nonce),
            ephemeral_salt=int(ephemeral_salt),
            pad_bytes=0,
            aad=aad,
        )
        if self.print_events:
            logger.info(f"[{self.node_id}] VERIFY_REQ create session={str(session_id)[:8]}.. nonce={nonce}")
        hdr["payload"] = payload
        return hdr

    @_with_lock
    def process_verify_req(self, msg: Dict[str, Any], peer_id: str, ttl_s: float = 600.0) -> bool:
        # Validate challenge and expiry first; consume only after signature verifies.
        challenge_in_msg = str(msg.get("challenge", ""))
        rec = self._challenges.peek_if_valid(str(peer_id), challenge_in_msg)
        if rec is None:
            if self.print_events:
                logger.info(f"[{self.node_id}] VERIFY_REQ reject peer={peer_id} (no_pending_challenge)")
            return False
        challenge_str = str(rec.challenge)
        
        payload_list = msg.get("payload")
        if not isinstance(payload_list, list):
            if self.print_events:
                logger.info(f"[{self.node_id}] VERIFY_REQ reject peer={peer_id} (bad_payload_type)")
            return False

        e_salt = int(msg.get("ephemeral_salt", 0))
        sess_id = str(msg.get("session_id", ""))
        nonce = int(msg.get("nonce", 0))
        
        _hdr, aad = verify_req_aad(
            field_profile_id=str(getattr(self, "field_profile_id", "")),
            challenge=str(challenge_str),
            session_id=str(sess_id),
            nonce=int(nonce),
            ephemeral_salt=int(e_salt),
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
                logger.info(f"[{self.node_id}] VERIFY_REQ reject peer={peer_id} reason={reason}")
            return False

        # Consume challenge on success (one-time use).
        # Must succeed; otherwise another thread consumed it first.
        if not self._challenges.consume(str(peer_id), challenge_in_msg):
            if self.print_events:
                logger.info(f"[{self.node_id}] VERIFY_REQ reject peer={peer_id} (challenge_already_used)")
            return False

        # Epoch Anchor: Initialize rolling chain hash
        genesis_key = genesis_chain_hash(int(self.seed), str(sess_id))
        
        # Neural Codec Init
        codec = NeuralCodec(codec_session_key(int(self.seed), str(sess_id)), role="responder")
        
        # Ouroboros: Initialize Ratchet Key from Root Seed + Session ID
        ratchet_key = kdf_int(int(self.seed), f"INIT::{sess_id}")

        new_session = HiveSession(
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
        
        # Multiverse: Initialize Timeline (Clear old forks if new handshake)
        self.timelines[peer_id] = [new_session]
        
        if self.print_events:
            logger.info(f"[{self.node_id}] SESSION ESTABLISHED with {peer_id} (sid={sess_id})")
        return True

    def force_session(self, peer_id: str, session_id: str, ephemeral_salt: int):
        # Epoch Anchor: Initialize rolling chain hash
        chain_hash = forced_chain_hash(int(self.seed), str(session_id))
        
        # Neural Codec Init
        codec = NeuralCodec(codec_session_key(int(self.seed), str(session_id)), role="forced")

        # Ouroboros: Initialize Ratchet Key
        ratchet_key = kdf_int(int(self.seed), f"INIT::{session_id}")

        new_session = HiveSession(
            session_id=session_id,
            peer_id=str(peer_id),
            start_time=time.time(),
            ttl_s=3600.0,
            ephemeral_salt=ephemeral_salt,
            chain_hash=chain_hash,
            out_seq=1,
            in_seq=1,
            codec=codec,
            ratchet_key=ratchet_key
        )
        self.timelines[peer_id] = [new_session]
        
        if self.print_events:
            logger.info(f"[{self.node_id}] SESSION FORCED with {peer_id} (sid={session_id})")

    def rollback_anchor(self, peer_id: str) -> bool:
        """Rollback Epoch Anchor to previous state if delivery failed."""
        dst = str(peer_id)
        if dst not in self.timelines or not self.timelines[dst]:
             return False
        
        # Roll back all active timelines for this peer.
        for sess in self.timelines[dst]:
            if sess.prev_chain_hash:
                sess.chain_hash = sess.prev_chain_hash
                sess.prev_chain_hash = b""
        
        if self.print_events:
             logger.info(f"[{self.node_id}] ROLLBACK ANCHOR peer={dst}")
        return True

    @_with_lock
    def ingest_finalized_block(self, block_hash: str):
        """
        The Ouroboros Trigger.
        Called when the Substrate Light Client confirms a new finalized block.
        Rotates ALL session keys (in ALL timelines) forward. Forward Secrecy is immediate.
        """
        if self.print_events:
            logger.info(f"[*] Ouroboros: Ingesting Reality {block_hash[:8]}...")
        
        for peer_id, timelines in self.timelines.items():
            for sess in timelines:
                if sess.ratchet_key is None:
                    continue # Skip legacy sessions
                
                # 1. Evolve the Key
                # Next_Key = HMAC(Current_Key, Block_Hash || Pepper)
                old_key_fragment = str(sess.ratchet_key)[:8]
                
                mix_data = str(block_hash)
                if self.pepper:
                    mix_data += f":{self.pepper}"

                sess.ratchet_key = kdf_int(int(sess.ratchet_key), mix_data)
                
                # 2. Update Metadata
                sess.last_ratchet_hash = block_hash
                
                if self.print_events:
                    logger.info(f"    [>] Session {sess.session_id[:6]} ({peer_id}): Ratcheted {old_key_fragment}... -> {str(sess.ratchet_key)[:8]}...")

    @property
    def sessions(self) -> Dict[str, HiveSession]:
        """Backward compatibility view: returns primary timeline for each peer."""
        return {pid: tls[0] for pid, tls in self.timelines.items() if tls}

    def _prune_timelines(self, peer_id: str, winner: HiveSession):
        """Collapse the multiverse to the winning timeline."""
        # In a full implementation, we might keep some backups, but for "Shattered Glass" PoC,
        # we collapse to the single truth immediately to save resources.
        self.timelines[peer_id] = [winner]

    @_with_lock
    def send(
        self,
        dst_node_id: str,
        content: str,
        pad_bytes: int = 0,
        *,
        override_created_at_ms: Optional[int] = None,
        override_expires_at_ms: Optional[int] = None,
        encrypt_headers: bool = False,
    ) -> Dict[str, Any]:
        dst = str(dst_node_id)
        if dst not in self.timelines or not self.timelines[dst]:
            if self.print_events:
                logger.info(f"[{self.node_id}] SEND blocked dst={dst} (no_session)")
            return {}
        
        # Always send on the PRIMARY timeline (Index 0).
        # In a Multiverse, we emit based on our "Best Guess" reality.
        # If we are forked, Index 0 should represent the "Optimist" (Main) or "Winner".
        sess = self.timelines[dst][0]
        
        if not sess.is_valid():
            if self.print_events:
                logger.info(f"[{self.node_id}] SEND blocked dst={dst} (session_expired)")
            return {}

        nonce = secrets.randbits(64)
        while sess.seen.contains(nonce):
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
        aad_with_anchor = aad_with_epoch_anchor(aad, chain_hash=sess.chain_hash, seq=sess.out_seq)

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
            # Epoch Anchor: Update rolling chain hash (with rollback support)
            sess.prev_chain_hash = sess.chain_hash
            sess.chain_hash = update_chain_hash(sess.chain_hash, sess.out_seq)

        except Exception as e:
            # Revert sequence on failure to ensure next try matches
            sess.out_seq -= 1
            if self.print_events:
                 logger.info(f"[{self.node_id}] SEND blocked dst={dst} ({repr(e)})")
            return {}

        if self.print_events:
            plen = len(payload) if isinstance(payload, list) else -1
            logger.info(f"[{self.node_id}] SENT dst={dst} nonce={nonce} payload_len={plen} seq={sess.out_seq}")
        header["payload"] = payload

        # Encrypted header mode: wrap the plaintext header in an opaque blob
        if encrypt_headers:
            from .protocol import encrypt_header, derive_route_tag
            bits = self.fingerprint_bits(self.seed, mutate=False)
            epoch = int(time.time()) // 60
            enc_hdr = encrypt_header(header, bits, sess.session_id, int(nonce))
            route_tag = derive_route_tag(bits, epoch)
            return {
                "route_tag": route_tag.hex(),
                "encrypted_header": enc_hdr.hex(),
                "payload": payload,
                "session_id": sess.session_id,  # needed for header decryption
                "nonce": int(nonce),             # needed for header decryption
            }

        return header

    @_with_lock
    def receive(self, msg: Dict[str, Any], prev_hop_id: str) -> Dict[str, Any]:
        prev = str(prev_hop_id)
        if prev not in self.sessions: # Note: self.sessions is the property view, but self.timelines has the real data
            # Check timelines directly
            if prev not in self.timelines or not self.timelines[prev]:
                if self.print_events:
                    logger.info(f"[{self.node_id}] RECV reject from={prev} reason=unknown_session")
                return {"status": "reject", "reason": "unknown_session"}

        # Detect encrypted header mode
        if "encrypted_header" in msg and "route_tag" in msg:
            from .protocol import decrypt_header, derive_route_tag
            epoch = int(time.time()) // 60
            bits = self.fingerprint_bits(self.seed, mutate=False)
            
            # Validate Route Tag (+/- 1 epoch window)
            tag_hex = str(msg["route_tag"])
            tag_valid = False
            for dx in (0, -1, 1):
                if derive_route_tag(bits, epoch + dx).hex() == tag_hex:
                    tag_valid = True
                    break
            
            if not tag_valid:
                if self.print_events:
                    logger.info(f"[{self.node_id}] RECV reject from={prev} reason=invalid_route_tag")
                return {"status": "reject", "reason": "invalid_route_tag"}

            outer_payload = msg.get("payload")  # save before overwriting
            enc_bytes = bytes.fromhex(str(msg["encrypted_header"]))
            sid_hint = str(msg.get("session_id", ""))
            nonce_hint = int(msg.get("nonce", 0))
            ok, decrypted_hdr = decrypt_header(enc_bytes, bits, sid_hint, nonce_hint)
            if not ok:
                if self.print_events:
                    logger.info(f"[{self.node_id}] RECV reject from={prev} reason=header_decrypt_failed")
                return {"status": "reject", "reason": "header_decrypt_failed"}
            # The encrypted header includes the full dict with payload key,
            # but the payload list itself was carried in the outer message for efficiency.
            msg = dict(decrypted_hdr)
            if outer_payload is not None and isinstance(outer_payload, list):
                msg["payload"] = outer_payload

        if str(msg.get("field_profile_id", "")) != str(getattr(self, "field_profile_id", "")):
            if self.print_events:
                logger.info(f"[{self.node_id}] RECV reject from={prev} reason=wrong_profile")
            return {"status": "reject", "reason": "wrong_profile"}


        nonce = int(msg.get("nonce", 0))
        
        
        created_at_ms = int(msg.get("created_at_ms", 0) or 0)
        expires_at_ms = int(msg.get("expires_at_ms", 0) or 0)
        # ... checks ...
        if created_at_ms <= 0 or expires_at_ms <= 0:
            if self.print_events: logger.info(f"[{self.node_id}] RECV reject from={prev} reason=bad_time")
            return {"status": "reject", "reason": "bad_time"}
        now_ms = _now_ms()
        if now_ms > int(expires_at_ms):
            if self.print_events: logger.info(f"[{self.node_id}] RECV reject from={prev} reason=expired")
            return {"status": "reject", "reason": "expired"}
        if int(created_at_ms) > int(now_ms) + int(self.skew_ms):
            if self.print_events: logger.info(f"[{self.node_id}] RECV reject from={prev} reason=clock_skew")
            return {"status": "reject", "reason": "clock_skew"}
        if int(expires_at_ms) - int(created_at_ms) > int(self.max_ttl_ms):
            if self.print_events: logger.info(f"[{self.node_id}] RECV reject from={prev} reason=ttl_too_long")
            return {"status": "reject", "reason": "ttl_too_long"}

        payload = msg.get("payload")
        if not isinstance(payload, list):
            if self.print_events: logger.info(f"[{self.node_id}] RECV reject from={prev} reason=bad_payload")
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
        base_aad = canonical_json(header)
        
        # Multiverse: Iterate active timelines
        candidates = list(self.timelines.get(prev, []))
        
        window_size = 5
        valid_decrypt = False
        winner_sess = None
        blob_found = None
        seq_found = -1
        acks_found = []
        
        replay_detected = False
        candidates_checked = 0
        
        # We try every candidate. If healing is on, we also trying FORKING them.
        for sess in candidates:
            if not sess.is_valid(): continue
            candidates_checked += 1
            if sess.seen.contains(nonce): 
                replay_detected = True
                continue # Replay check per session
            
            base_seq = sess.in_seq + 1
            
            # 1. Sovereign Trial (Current State)
            for offset in range(window_size + 1):
                c_seq = base_seq + offset
                aad = aad_with_epoch_anchor(base_aad, chain_hash=sess.chain_hash, seq=c_seq)
                
                b, r, a, t = self.decrypt_bytes(
                    payload, session_id=sess.session_id, nonce=nonce, ephemeral_salt=sess.ephemeral_salt, 
                    aad=aad, codec=sess.codec, ratchet_key=sess.ratchet_key
                )
                if b is not None:
                    valid_decrypt = True
                    winner_sess = sess
                    blob_found, acks_found, seq_found = b, a, c_seq
                    break
            
            if valid_decrypt: break

            # 2. Resonant Trial (Phantom Key / Fork)
            if self.healing_mode == "multiverse":
                # Limit active forks to 2 (User Request)
                if len(self.timelines.get(prev, [])) >= 2:
                    if self.print_events:
                        logger.info(f"[{self.node_id}] MULTIVERSE: Skip fork (Limit 2 reached)")
                    continue

                # Try to HEAL by fast-forwarding the Chain Hash for skipped packets
                # We assume no payload dependency, so we can derive H_t from H_{t-n} + Seqs.
                for offset in range(1, window_size + 1):
                    c_seq = base_seq + offset
                    
                    # Fast-forward hash from base_seq to c_seq - 1
                    phantom_hash = sess.chain_hash
                    for skipped in range(base_seq, c_seq):
                         phantom_hash = update_chain_hash(phantom_hash, skipped)
                    
                    # Now try decrypt with proper phantom_hash
                    aad_phantom = aad_with_epoch_anchor(base_aad, chain_hash=phantom_hash, seq=c_seq)
                    
                    # Note: We still use current ratchet_key. 
                    # If Plasticity (Lattice Evolution) is required, we fail here unless backend is Frozen.
                    # TODO: Simulate Lattice Evolution for Phantom Request? 
                    # For now, we assume Frozen or "Slow Drift" where key is valid for window.
                    
                    b2, r2, a2, t2 = self.decrypt_bytes(
                        payload, session_id=sess.session_id, nonce=nonce, ephemeral_salt=sess.ephemeral_salt, 
                        aad=aad_phantom, codec=sess.codec, ratchet_key=sess.ratchet_key
                    )
                    if b2 is not None:
                        # SUCCESS!
                        recall_phantom = sess.clone()
                        recall_phantom.chain_hash = phantom_hash # Fast-forwarded state
                        # Evolve logic handles the *current* packet, but we missed evolution for skipped packets?
                        # If backend=lattice, we are desynced in LATTICE state.
                        # Ideally we call `_evolve_lattice(seed)` 'offset' times.
                        # But we can't do that safely on shared lattice.
                        # So this Healing only works for "Frozen" backend or "Robust" Neural Codec.
                        
                        winner_sess = recall_phantom
                        blob_found, acks_found, seq_found = b2, a2, c_seq
                        valid_decrypt = True
                        if self.print_events:
                            logger.info(f"[{self.node_id}] MULTIVERSE: Phantom Timeline Verified! (Seq {c_seq})")
                        break
            
            if valid_decrypt: break
        
        if not valid_decrypt:
             if replay_detected:
                 if self.print_events:
                     logger.info(f"[{self.node_id}] RECV reject from={prev} reason=replay")
                 return {"status": "reject", "reason": "replay"}
             if self.print_events:
                 logger.info(f"[{self.node_id}] RECV reject from={prev} reason=mac_mismatch")
             return {"status": "reject", "reason": "mac_mismatch"}

        # COLLAPSE: Winner takes all.
        if len(self.timelines[prev]) > 1 or winner_sess not in self.timelines[prev]:
            if self.print_events:
                logger.info(f"[{self.node_id}] MULTIVERSE: Collapse! Winner={winner_sess.session_id} (Seq {seq_found})")
            self.timelines[prev] = [winner_sess]

        sess = winner_sess
        if acks_found:
             sess.pending_acks.extend(acks_found)

        # Update State (Gap Detection)
        if seq_found != sess.in_seq + 1:
            gap = seq_found - sess.in_seq - 1
            if self.print_events:
                logger.info(f"[{self.node_id}] RESILIENCE: Gap Detected! {sess.in_seq} -> {seq_found} (Missed {gap})")
        
        sess.in_seq = seq_found
        sess.chain_hash = update_chain_hash(sess.chain_hash, sess.in_seq)

        # Decode Content (Vocab or Text)
        if self.content_codec == "utf8":
            try:
                ok, text = unpack_plaintext(bytes(blob_found))
                if not ok:
                     if self.print_events: logger.info(f"[{self.node_id}] RECV reject from={prev} reason=unpack_error")
                     return {"status": "reject", "reason": "unpack_error"}
            except Exception as e:
                if self.print_events:
                    logger.error("Exception occurred:", exc_info=True)
                    logger.info(f"[{self.node_id}] RECV error: {e}")
                return {"status": "reject", "reason": "unpack_error"}
        else: # Vocab Path
            ok_id, _reason_id, vid = vocab_peek_vocab_id(blob_found)
            if not ok_id:
                if self.print_events: logger.info(f"[{self.node_id}] RECV reject from={prev} reason=bad_plaintext")
                return {"status": "reject", "reason": "bad_plaintext"}
            
            assert self.vocab_registry is not None
            v = self.vocab_registry.get(bytes(vid))
            if v is None:
                if self.print_events: logger.info(f"[{self.node_id}] RECV reject from={prev} reason=wrong_vocab")
                return {"status": "reject", "reason": "wrong_vocab"}
            
            ok2, reason2, text = vocab_decode_text(blob_found, v, allow_literals=bool(self.vocab_allow_literals))
            if not ok2:
                if self.print_events: logger.info(f"[{self.node_id}] RECV reject from={prev} reason={reason2}")
                return {"status": "reject", "reason": reason2}

        # Success! Commit Nonce and Sequence
        sess.seen.check_and_add(nonce)

        if str(msg.get("dst_node_id")) == self.node_id:
            if self.print_deliveries:
                logger.info(f"[DELIVERED to {self.node_id} from {prev}] {text}")
            return {"status": "delivered"}
        
        msg_dst = str(msg.get("dst_node_id"))
        if self.print_events:
            logger.info(f"[{self.node_id}] RECV reject from={prev} reason=no_forward dst={msg_dst}")
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
                        logger.info(f"[{self.node_id}] OFFLINE_RECOVER seed={seed_candidate} profile={self.field_profile_id}")
                    
                    try:
                        text = pt.decode("utf-8")
                        if self.print_deliveries:
                            logger.info(f"[OFFLINE RECOVERED] {text}")
                        return True, "ok", text
                    except Exception:
                        return True, "ok_binary", pt.hex()

            except Exception:
                continue
        
        return False, "decrypt_failed", None
