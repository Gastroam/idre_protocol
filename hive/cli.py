
import argparse
import os
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
from typing import Dict, Optional
from hive.node import FieldBoundNode
from hive.utils import (
    DEFAULT_MAX_PAYLOAD_INTS,
    DEFAULT_MAX_BODY_BYTES,
    DEFAULT_CHALLENGE_TTL_MS,
    DEFAULT_SKEW_MS,
    DEFAULT_MAX_TTL_MS,
    DEFAULT_DEFAULT_TTL_MS,
    DEFAULT_MAX_PENDING_CHALLENGES,
    DEFAULT_MAX_CT_LEN,
)
from core.vocab_codec import Vocab, load_vocab_registry

# Defaults
DEFAULT_RL_CHALLENGE_RPS = 5.0
DEFAULT_RL_CHALLENGE_BURST = 10.0
DEFAULT_RL_VERIFY_RPS = 2.0
DEFAULT_RL_VERIFY_BURST = 5.0
DEFAULT_RL_RECEIVE_RPS = 10.0
DEFAULT_RL_RECEIVE_BURST = 50.0

def parse_int_tuple(value: str):
    """Parses a comma-separated string of integers into a tuple."""
    if not value:
        return tuple()
    out = []
    for part in str(value).split(","):
        part = part.strip()
        if not part:
            continue
        out.append(int(part))
    return tuple(out)

def get_node_argparser(description="Hive Node Server") -> argparse.ArgumentParser:
    """Creates and returns the ArgumentParser for the Hive node."""
    ap = argparse.ArgumentParser(description=description)
    ap.add_argument(
        "--protocol-version",
        choices=["v2", "v3"],
        default="v2",
        help="Explicit protocol version selection. v3 never falls back to v2.",
    )
    ap.add_argument("--port", type=int, default=8890)
    ap.add_argument("--node-id", type=str, required=True)
    ap.add_argument("--seed", type=int, default=7245)
    
    # Physics Params
    ap.add_argument("--anchor-seeds", type=str, default="7245")
    ap.add_argument("--anchor-weight", type=float, default=80.0)
    ap.add_argument("--n-angles", type=int, default=72)
    ap.add_argument("--scan-resolution", type=int, default=50)
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--planes", type=int, default=4, help="Number of locked planes to concatenate into the fingerprint.")
    ap.add_argument("--tau-frac", type=float, default=0.55, help="tau = projection_amplitude * tau_frac")
    ap.add_argument("--print-deliveries", action=argparse.BooleanOptionalAction, default=False)
    ap.add_argument("--print-events", action=argparse.BooleanOptionalAction, default=False)
    ap.add_argument("--enable-plasticity", action=argparse.BooleanOptionalAction, default=False)
    ap.add_argument("--freeze-field", action=argparse.BooleanOptionalAction, default=False)
    ap.add_argument("--healing-mode", type=str, default="none")
    ap.add_argument("--pepper", type=str, default="", help="Crucial security parameter (domain separator for PRF).")
    ap.add_argument("--backend", type=str, default="lattice")
    
    # Backend / Mode
    # Limits & Protocol
    ap.add_argument("--max-body-bytes", type=int, default=DEFAULT_MAX_BODY_BYTES)
    ap.add_argument("--max-payload-ints", type=int, default=DEFAULT_MAX_PAYLOAD_INTS)
    ap.add_argument("--max-ct-len", type=int, default=DEFAULT_MAX_CT_LEN)
    ap.add_argument("--max-pending-challenges", type=int, default=DEFAULT_MAX_PENDING_CHALLENGES)
    ap.add_argument("--challenge-ttl-ms", type=int, default=DEFAULT_CHALLENGE_TTL_MS)
    ap.add_argument("--skew-ms", type=int, default=DEFAULT_SKEW_MS)
    ap.add_argument("--max-ttl-ms", type=int, default=DEFAULT_MAX_TTL_MS)
    ap.add_argument("--default-ttl-ms", type=int, default=DEFAULT_DEFAULT_TTL_MS)
    
    # Rate Limiting
    ap.add_argument("--rl-challenge-rps", type=float, default=DEFAULT_RL_CHALLENGE_RPS)
    ap.add_argument("--rl-challenge-burst", type=float, default=DEFAULT_RL_CHALLENGE_BURST)
    ap.add_argument("--rl-verify-rps", type=float, default=DEFAULT_RL_VERIFY_RPS)
    ap.add_argument("--rl-verify-burst", type=float, default=DEFAULT_RL_VERIFY_BURST)
    ap.add_argument("--rl-receive-rps", type=float, default=DEFAULT_RL_RECEIVE_RPS)
    ap.add_argument("--rl-receive-burst", type=float, default=DEFAULT_RL_RECEIVE_BURST)
    
    # Codec / Vocab
    ap.add_argument("--content-codec", choices=["utf8", "vocab"], default="utf8")
    ap.add_argument("--vocab-file", action="append", default=["vocab.jsonl"], help="Defaults to vocab.jsonl if not provided.")
    ap.add_argument("--vocab-allow-literals", action=argparse.BooleanOptionalAction, default=True)
    ap.add_argument("--max-plaintext-bytes", type=int, default=65535)
    
    # Offline Recovery
    ap.add_argument(
        "--offline-seed-ring",
        type=str,
        default="",
        help="Comma-separated list of seeds for offline ghost recovery. INTERNAL ONLY.",
    )

    # IDRE v3 Provisioning & Durable Store options (used only when --protocol-version v3)
    ap.add_argument("--state-db", type=str, default="", help="SQLite durable state store path (v3).")
    ap.add_argument("--bundle-id-hex", type=str, default="", help="16-byte opaque public bundle ID hex (v3).")
    ap.add_argument("--expected-vocab-digest-hex", type=str, default="", help="32-byte trusted vocab SHA-256 hex (v3).")
    ap.add_argument("--network-secret-hex", type=str, default="", help=">=32-byte network secret hex (or IDRE_V3_NETWORK_SECRET_HEX).")
    ap.add_argument("--field-init-secret-hex", type=str, default="", help=">=32-byte field init secret hex (or IDRE_V3_FIELD_INIT_SECRET_HEX).")
    ap.add_argument("--storage-key-hex", type=str, default="", help=">=32-byte local store MAC key hex (or IDRE_V3_STORAGE_KEY_HEX).")
    ap.add_argument("--encrypted-headers", action=argparse.BooleanOptionalAction, default=False)
    ap.add_argument("--adaptive-codec", action=argparse.BooleanOptionalAction, default=False)

    return ap

def configure_node_from_args(args) -> FieldBoundNode:
    """Instantiates and configures a FieldBoundNode based on parsed CLI arguments."""
    protocol_version = str(getattr(args, "protocol_version", "v2")).strip().lower()
    if protocol_version == "v3":
        from core.profile_v3 import (
            ProfileV3,
            ProfileValidationError,
            ProvisioningBundleV3,
            max_usable_payload_bytes,
        )
        from core.vocab_v3 import load_vocab_strict_v3
        from hive.node_v3 import FieldBoundNodeV3

        if str(args.backend).lower().strip() != "lattice":
            raise ProfileValidationError("v3 requires --backend lattice (frozen mode is forbidden)")
        if not bool(args.enable_plasticity):
            raise ProfileValidationError("v3 requires --enable-plasticity")
        if bool(args.freeze_field):
            raise ProfileValidationError("v3 forbids --freeze-field")
        if str(args.content_codec).strip().lower() != "vocab":
            raise ProfileValidationError("v3 requires --content-codec vocab")
        if bool(args.vocab_allow_literals):
            raise ProfileValidationError("v3 requires --no-vocab-allow-literals")
        if str(args.healing_mode).strip().lower() != "none":
            raise ProfileValidationError("v3 requires --healing-mode none")
        if str(getattr(args, "offline_seed_ring", "")).strip():
            raise ProfileValidationError("v3 forbids --offline-seed-ring")

        enc_hdrs = bool(getattr(args, "encrypted_headers", False))
        usable = max_usable_payload_bytes(encrypted_headers=enc_hdrs)
        if int(args.max_plaintext_bytes) > usable:
            raise ProfileValidationError(
                f"v3 --max-plaintext-bytes ({args.max_plaintext_bytes}) exceeds usable cell capacity ({usable})"
            )

        bundle_id_hex = str(getattr(args, "bundle_id_hex", "")).strip()
        vocab_dig_hex = str(getattr(args, "expected_vocab_digest_hex", "")).strip()
        net_hex = str(getattr(args, "network_secret_hex", "") or os.environ.get("IDRE_V3_NETWORK_SECRET_HEX", "")).strip()
        fld_hex = str(getattr(args, "field_init_secret_hex", "") or os.environ.get("IDRE_V3_FIELD_INIT_SECRET_HEX", "")).strip()
        store_hex = str(getattr(args, "storage_key_hex", "") or os.environ.get("IDRE_V3_STORAGE_KEY_HEX", "")).strip()
        state_db = str(getattr(args, "state_db", "")).strip()

        if not (bundle_id_hex and vocab_dig_hex and net_hex and fld_hex and store_hex and state_db):
            raise ProfileValidationError(
                "v3 requires --state-db, --bundle-id-hex, --expected-vocab-digest-hex, "
                "--network-secret-hex, --field-init-secret-hex, and --storage-key-hex (refusing to fall back to v2)"
            )

        bundle_id = bytes.fromhex(bundle_id_hex)
        expected_digest = bytes.fromhex(vocab_dig_hex)
        vocab_files = list(args.vocab_file or [])
        if len(vocab_files) != 1:
            raise ProfileValidationError("v3 requires exactly one --vocab-file")
        vocab_v3 = load_vocab_strict_v3(vocab_files[0], expected_vocab_digest=expected_digest)
        profile = ProfileV3(
            bundle_id=bundle_id,
            expected_vocab_digest=expected_digest,
            encrypted_headers=enc_hdrs,
            adaptive_codec_enabled=bool(getattr(args, "adaptive_codec", False)),
            max_plaintext_bytes=int(args.max_plaintext_bytes),
        )
        bundle = ProvisioningBundleV3(
            profile=profile,
            network_secret=bytes.fromhex(net_hex),
            field_init_secret=bytes.fromhex(fld_hex),
            expected_vocab_digest=expected_digest,
            local_node_id=str(args.node_id),
        )
        return FieldBoundNodeV3(
            bundle=bundle,
            vocab=vocab_v3,
            db_path=state_db,
            storage_key=bytes.fromhex(store_hex),
        )

    vocab: Optional[Vocab] = None
    vocab_registry: Optional[Dict[bytes, Vocab]] = None
    # IDRE v3: Vocab is MANDATORY for Substrate Initialization (Vector Space Folding)
    # regardless of content_codec.
    if not args.vocab_file:
         # Should be covered by default=["vocab.jsonl"] but safety first
         args.vocab_file = ["vocab.jsonl"]
    
    try:
        vocab_registry, vocab = load_vocab_registry([str(x) for x in args.vocab_file])
    except Exception as e:
        logger.info(f"[hive.cli] WARNING: Failed to load vocab: {e}")
        vocab = None
        vocab_registry = None

    # Ensure pepper is explicitly provisioned.
    pepper = args.pepper or os.environ.get("IDRE_PEPPER")
    if not pepper:
        raise SystemExit("ERROR: missing pepper. Set --pepper or IDRE_PEPPER.")

    if args.port <= 0:
        args.port = 8890

    node = FieldBoundNode(
        node_id=args.node_id,
        seed=args.seed,
        anchor_seeds=parse_int_tuple(args.anchor_seeds) or (7245,),
        anchor_weight=args.anchor_weight,
        n_angles=args.n_angles,
        scan_resolution=args.scan_resolution,
        threshold=args.threshold,
        planes=args.planes,
        tau_frac=args.tau_frac,
        print_deliveries=bool(args.print_deliveries),
        print_events=bool(args.print_events),
        freeze_field=bool(args.freeze_field),
        backend=str(args.backend),
        content_codec=str(args.content_codec),
        vocab=vocab,
        vocab_registry=vocab_registry,
        vocab_allow_literals=bool(args.vocab_allow_literals),
        max_plaintext_bytes=int(args.max_plaintext_bytes),
        plasticity=bool(args.enable_plasticity),
        healing_mode=str(args.healing_mode),
        pepper=str(pepper),
    )
    
    # Protocol Limits
    node.challenge_ttl_ms = int(args.challenge_ttl_ms)
    node.skew_ms = int(args.skew_ms)
    node.max_ttl_ms = int(args.max_ttl_ms)
    node.default_ttl_ms = int(args.default_ttl_ms)
    node.max_pending_challenges = int(args.max_pending_challenges)
    node.max_payload_ints = int(args.max_payload_ints)
    node.max_ct_len = int(args.max_ct_len)
    
    # Offline Seed Ring
    if args.offline_seed_ring:
        try:
            seeds = [int(s.strip()) for s in args.offline_seed_ring.split(",") if s.strip()]
            node.offline_seed_ring = seeds
            logger.info(f"[hive.cli] Offline Ghost Ring loaded: {len(seeds)} seeds")
        except ValueError:
            raise SystemExit("ERROR: --offline-seed-ring must be comma-separated integers")
            
    return node
