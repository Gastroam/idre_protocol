#!/usr/bin/env python3
import sys
from pathlib import Path

# Add repo root to sys.path (parent of idre_clean folder)
# This assumes the script is located at .../idre_clean/scripts/hive_v12_node_server.py

from hive.server import _ThreadedHTTPServer, Handler, TokenBucketLimiter

# Defaults
DEFAULT_RL_CHALLENGE_RPS = 5.0
DEFAULT_RL_CHALLENGE_BURST = 10.0
DEFAULT_RL_VERIFY_RPS = 2.0
DEFAULT_RL_VERIFY_BURST = 5.0

from hive.cli import get_node_argparser, configure_node_from_args

def main() -> int:
    ap = get_node_argparser()
    args = ap.parse_args()

    node = configure_node_from_args(args)

    httpd = _ThreadedHTTPServer(("127.0.0.1", int(args.port)), Handler)
    httpd.node = node  # type: ignore[attr-defined]
    httpd.max_body_bytes = int(args.max_body_bytes)  # type: ignore[attr-defined]
    httpd.rl_challenge_ip = TokenBucketLimiter(rate_per_s=float(args.rl_challenge_rps), burst=float(args.rl_challenge_burst))  # type: ignore[attr-defined]
    httpd.rl_verify_ip = TokenBucketLimiter(rate_per_s=float(args.rl_verify_rps), burst=float(args.rl_verify_burst))  # type: ignore[attr-defined]
    httpd.rl_receive_ip = TokenBucketLimiter(rate_per_s=float(args.rl_receive_rps), burst=float(args.rl_receive_burst)) # type: ignore[attr-defined]

    print(
        f"[hive_v12_node_server] node_id={node.node_id} seed={node.seed} port={args.port} "
        f"planes={args.planes} tau_frac={args.tau_frac} backend={args.backend}"
    )

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        return 0

if __name__ == "__main__":
    raise SystemExit(main())
