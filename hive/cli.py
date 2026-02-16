
import argparse
from typing import Dict, Optional
from idre_clean.hive.node import FieldBoundNode
from idre_clean.hive.utils import (
    DEFAULT_MAX_PAYLOAD_INTS,
    DEFAULT_MAX_BODY_BYTES,
    DEFAULT_CHALLENGE_TTL_MS,
    DEFAULT_SKEW_MS,
    DEFAULT_MAX_TTL_MS,
    DEFAULT_DEFAULT_TTL_MS,
    DEFAULT_MAX_PENDING_CHALLENGES,
    DEFAULT_MAX_CT_LEN,
)
from idre_clean.core.vocab_codec import Vocab, load_vocab_registry

# Defaults
DEFAULT_RL_CHALLENGE_RPS = 5.0
DEFAULT_RL_CHALLENGE_BURST = 10.0
DEFAULT_RL_VERIFY_RPS = 2.0
DEFAULT_RL_VERIFY_BURST = 5.0

def parse_int_tuple(value: str):
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
    ap = argparse.ArgumentParser(description=description)
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
    
    return ap

def configure_node_from_args(args) -> FieldBoundNode:
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
        # Fallback for testing/CI if vocab.jsonl is missing?
        # No, strict security. But for now, let's print a warning and let it fail if file missing.
        print(f"[hive.cli] WARNING: Failed to load vocab: {e}")
        # Proceeding might fail in Node __init__
        vocab = None
        vocab_registry = None

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
            print(f"[hive.cli] Offline Ghost Ring loaded: {len(seeds)} seeds")
        except ValueError:
            raise SystemExit("ERROR: --offline-seed-ring must be comma-separated integers")
            
    return node
