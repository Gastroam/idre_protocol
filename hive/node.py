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
from .session import HiveSession, PendingChallenge, NonceWindow



@dataclass(frozen=True)
class _FrozenNeuron:
    weights: np.ndarray
    bias: float = 0.0


class FrozenSubstrate:
    """Weights-only substrate for Option A (frozen)."""

    def __init__(self, *, embedding_dim: int, seed_scales: Dict[int, float], bias: float = 0.0):
        self.embedding_dim = int(embedding_dim)
        self.bias = float(bias)
        self._neurons: Dict[int, _FrozenNeuron] = {}
        for seed, scale in seed_scales.items():
            s = int(seed)
            sc = float(scale)
            w = seeded_unit_vector(s, self.embedding_dim) * sc
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
    ):
        self.node_id = str(node_id)
        self.seed = int(seed)
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
            self._frozen = FrozenSubstrate(embedding_dim=self.embedding_dim, seed_scales=seed_scales, bias=0.0)
        else:
            # Add parent dir to sys.path
            import sys
            root = Path(__file__).resolve().parent.parent.parent # idre_clean repo via relative path from hive/node.py? No, idre_clean/hive/node.py -> idre_clean is parent.
            # No, idre_clean/hive/node.py -> ../.. is root.
            # But the original code relied on _REPO_PARENT computed relative to script.
            # We assume imports work now.
            
            try:
                from idre_clean.vendor.mti_evo.core.lattice import HolographicLattice
            except Exception:
                try:
                    from vendor.mti_evo.core.lattice import HolographicLattice
                except Exception:
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

        out: List[int] = []
        for i, (u, w) in enumerate(self._plane_list):
            tau = self._tau_for_weights(weights, plane_idx=i)
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
                )
            )
        return out

    def fingerprint_bits(self, seed: Optional[int] = None, mutate: bool = True) -> List[int]:
        s = int(self.seed if seed is None else seed)
        if self.freeze_field and self._cached_bits is not None and s == int(self.seed):
            return list(self._cached_bits)
        
        # Note: If we use cache, we skip mutation? 
        # If freeze_field=True, plasticity is usually False/Ignored.
        
        bits = self._compute_fingerprint_bits(s, mutate=mutate)
        
        if self.freeze_field and s == int(self.seed):
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

    def _crypt(self, *, framed: List[int], session_id: str, nonce: int, ephemeral_salt: int, encrypt: bool, mutate: bool = True) -> List[int]:
        block_size = 32
        bits = self.fingerprint_bits(self.seed, mutate=mutate)
        combined = f"{session_id}:{int(ephemeral_salt)}:{int(nonce)}"

        if encrypt:
            pt = framed
            while len(pt) % block_size != 0:
                pt.append(0)
            out: List[int] = []
            for idx in range(len(pt) // block_size):
                chunk = pt[idx * block_size : (idx + 1) * block_size]
                salt = compute_block_salt(bits, combined, idx)
                k_t, pi_t = derive_keystream_and_permutation(salt, block_size)
                out.extend(xor_bytes(permute(chunk, pi_t), k_t))
            return out

        ct = framed
        if len(ct) % block_size != 0:
            ct = ct[: (len(ct) // block_size) * block_size]
        out = []
        for idx in range(len(ct) // block_size):
            chunk = ct[idx * block_size : (idx + 1) * block_size]
            salt = compute_block_salt(bits, combined, idx)
            k_t, pi_t = derive_keystream_and_permutation(salt, block_size)
            out.extend(inverse_permute(xor_bytes(chunk, k_t), pi_t))
        return out

    def _mac_key(self, *, session_id: str, nonce: int, ephemeral_salt: int, mutate: bool = True) -> bytes:
        bits = self.fingerprint_bits(self.seed, mutate=mutate)
        bits_bytes = bytes(int(b) & 1 for b in bits)
        ctx = f"{session_id}:{int(ephemeral_salt)}:{int(nonce)}".encode("utf-8")
        return _sha256(b"MACKEY/" + bits_bytes + b":" + ctx)

    def encrypt_message(
        self,
        message: str,
        *,
        session_id: str,
        nonce: int,
        ephemeral_salt: int,
        pad_bytes: int = 0,
        aad: bytes = b"",
    ) -> List[int]:
        blob = pack_plaintext(message)
        return self.encrypt_bytes(
            bytes(blob),
            session_id=session_id,
            nonce=int(nonce),
            ephemeral_salt=int(ephemeral_salt),
            pad_bytes=int(pad_bytes),
            aad=aad,
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
    ) -> List[int]:
        data = bytes(plaintext)
        if len(data) > int(self.max_plaintext_bytes):
            raise ValueError("plaintext_too_large")
        blob = struct.pack(">I", int(len(data))) + data
        pt = [b for b in blob]
        # Encrypt & MAC using CURRENT state (mutate=False)
        ct = self._crypt(framed=pt, session_id=session_id, nonce=nonce, ephemeral_salt=ephemeral_salt, encrypt=True, mutate=False)
        key = self._mac_key(session_id=session_id, nonce=nonce, ephemeral_salt=ephemeral_salt, mutate=False)
        
        # Explicit State Evolution (Forward Secrecy)
        # We evolve ONLY after using the state for this packet.
        self._evolve_lattice(self.seed)
        
        tag = hmac.new(key, (aad or b"") + bytes(int(x) & 0xFF for x in ct), hashlib.sha256).digest()
        return frame_payload(ct, tag, pad_bytes=pad_bytes)

    def decrypt_message(
        self,
        payload: List[int],
        *,
        session_id: str,
        nonce: int,
        ephemeral_salt: int,
        aad: bytes = b"",
    ) -> Tuple[bool, str]:
        b, reason = self.decrypt_bytes(payload, session_id=session_id, nonce=int(nonce), ephemeral_salt=int(ephemeral_salt), aad=aad)
        if b is None:
            return False, reason
        return unpack_plaintext(bytes(b))

    def decrypt_bytes(
        self,
        payload: List[int],
        *,
        session_id: str,
        nonce: int,
        ephemeral_salt: int,
        aad: bytes = b"",
    ) -> Tuple[Optional[bytes], str]:
        # print(f"[DEBUG] decrypt_bytes entry. len={len(payload)}")
        try:
            ct, tag = unframe_payload(payload, max_ct_len=self.max_ct_len)
        except Exception as e:
             print(f"[DEBUG] unframe_payload failed: {e}")
             return None, "framing_error"

        if not ct or len(tag) != MAC_LEN:
             return None, "framing_error_empty"

        # Verify MAC using CURRENT state (mutate=False)
        key = self._mac_key(session_id=session_id, nonce=nonce, ephemeral_salt=ephemeral_salt, mutate=False)
        exp = hmac.new(key, (aad or b"") + bytes(int(x) & 0xFF for x in ct), hashlib.sha256).digest()
        if not hmac.compare_digest(exp, tag):
             # DO NOT EVOLVE ON MAC FAILURE
             return None, "mac_mismatch"
             
        # Decrypt (mutate=False)
        pt = self._crypt(framed=ct, session_id=session_id, nonce=nonce, ephemeral_salt=ephemeral_salt, encrypt=False, mutate=False)
        
        # MAC Verified & Decrypted: Now Commit Evolved State
        self._evolve_lattice(self.seed)
        blob = bytes(int(x) & 0xFF for x in pt)
        if len(blob) < 4:
             return None, "padding_error_short"
        try:
             n = struct.unpack(">I", blob[:4])[0]
             data = blob[4 : 4 + int(n)]
             if len(data) != int(n):
                  return None, "padding_error_len"
             return data, "ok"
        except Exception:
             return None, "padding_error_struct"

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
        payload = self.encrypt_message(
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

        valid, text = self.decrypt_message(
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
        genesis_input = f"{self.seed}:{sess_id}:GENESIS".encode("utf-8")
        chain_hash = hashlib.sha256(genesis_input).digest()

        self.sessions[peer_id] = HiveSession(
            session_id=sess_id,
            peer_id=str(peer_id),
            start_time=time.time(),
            ttl_s=float(ttl_s),
            ephemeral_salt=e_salt,
            chain_hash=chain_hash,
        )
        if self.print_events:
            print(f"[{self.node_id}] SESSION ESTABLISHED with {peer_id} (sid={sess_id})")
        
        del self.pending_challenges[peer_id]
        return True

    def force_session(self, peer_id: str, session_id: str, ephemeral_salt: int):
        # Epoch Anchor: Initialize rolling chain hash
        genesis_input = f"{self.seed}:{session_id}:GENESIS".encode("utf-8")
        chain_hash = hashlib.sha256(genesis_input).digest()
        
        self.sessions[peer_id] = HiveSession(
            session_id=session_id,
            peer_id=str(peer_id),
            start_time=time.time(),
            ttl_s=3600.0,
            ephemeral_salt=ephemeral_salt,
            chain_hash=chain_hash,
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
        # Epoch Anchor: Bind to rolling chain hash
        aad_with_anchor = aad + sess.chain_hash

        try:
            if self.content_codec == "utf8":
                payload = self.encrypt_message(
                    content,
                    session_id=sess.session_id,
                    nonce=int(nonce),
                    ephemeral_salt=int(sess.ephemeral_salt),
                    pad_bytes=int(pad_bytes),
                    aad=aad_with_anchor,
                )
            else:
                assert self.vocab is not None
                blob = vocab_encode_text(str(content), self.vocab, allow_literals=bool(self.vocab_allow_literals))
                payload = self.encrypt_bytes(
                    blob,
                    session_id=sess.session_id,
                    nonce=int(nonce),
                    ephemeral_salt=int(sess.ephemeral_salt),
                    pad_bytes=int(pad_bytes),
                    aad=aad_with_anchor,
                )
            
            # Epoch Anchor: Update rolling chain hash (with rollback support)
            payload_bytes = bytes(payload)
            sess.prev_chain_hash = sess.chain_hash
            sess.chain_hash = hashlib.sha256(sess.chain_hash + payload_bytes).digest()

        except Exception:
            if self.print_events:
                print(f"[{self.node_id}] SEND blocked dst={dst} (encode_failed)")
            return {}

        if self.print_events:
            plen = len(payload) if isinstance(payload, list) else -1
            print(f"[{self.node_id}] SENT dst={dst} nonce={nonce} payload_len={plen}")
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
        # Epoch Anchor: Bind to rolling chain hash
        aad_with_anchor = aad + sess.chain_hash

        if self.content_codec == "utf8":
            ok, result = self.decrypt_message(
                payload, session_id=sess.session_id, nonce=nonce, ephemeral_salt=sess.ephemeral_salt, aad=aad_with_anchor
            )
            if not ok:
                if self.print_events:
                    print(f"[{self.node_id}] RECV reject from={prev} reason={result} nonce={nonce}")
                return {"status": "reject", "reason": result}
            
            text = result
            # Epoch Anchor: Update rolling chain hash (UTF8 path)
            payload_bytes = bytes(payload)
            sess.chain_hash = hashlib.sha256(sess.chain_hash + payload_bytes).digest()

        else:
            blob, reason = self.decrypt_bytes(
                payload, session_id=sess.session_id, nonce=nonce, ephemeral_salt=sess.ephemeral_salt, aad=aad_with_anchor
            )
            if blob is None:
                if self.print_events:
                    print(f"[{self.node_id}] RECV reject from={prev} reason={reason} nonce={nonce}")
                return {"status": "reject", "reason": reason}

            # Epoch Anchor: Update rolling chain hash (Vocab path)
            payload_bytes = bytes(payload)
            sess.chain_hash = hashlib.sha256(sess.chain_hash + payload_bytes).digest()
            
            ok_id, _reason_id, vid = vocab_peek_vocab_id(blob)
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
            ok2, reason2, text = vocab_decode_text(blob, v, allow_literals=bool(self.vocab_allow_literals))
            if not ok2:
                if reason2 == "wrong_vocab":
                    if self.print_events:
                        print(f"[{self.node_id}] RECV reject from={prev} reason=wrong_vocab")
                    return {"status": "reject", "reason": "wrong_vocab"}
                if self.print_events:
                    print(f"[{self.node_id}] RECV reject from={prev} reason=bad_plaintext")
                return {"status": "reject", "reason": "bad_plaintext"}

        if not sess.seen.check_and_add(nonce):
            if self.print_events:
                print(f"[{self.node_id}] RECV reject from={prev} reason=replay nonce={nonce}")
            return {"status": "reject", "reason": "replay"}

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
