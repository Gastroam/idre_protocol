#!/usr/bin/env python3
"""Hive Node HTTP Server Launcher (explicit v2 / v3 dispatch)."""

from hive.cli import configure_node_from_args, get_node_argparser
from hive.node_v3 import FieldBoundNodeV3
from hive.server import Handler, TokenBucketLimiter, _ThreadedHTTPServer
from hive.server_v3 import create_server_v3

# Defaults
DEFAULT_RL_CHALLENGE_RPS = 5.0
DEFAULT_RL_CHALLENGE_BURST = 10.0
DEFAULT_RL_VERIFY_RPS = 2.0
DEFAULT_RL_VERIFY_BURST = 5.0


def build_server_from_args(args, *, host: str = "127.0.0.1"):
    """Construct the version-matched HTTP server for parsed CLI arguments."""
    node = configure_node_from_args(args)
    if isinstance(node, FieldBoundNodeV3):
        return create_server_v3(node, host=host, port=int(args.port)), node

    httpd = _ThreadedHTTPServer((host, int(args.port)), Handler)
    httpd.node = node  # type: ignore[attr-defined]
    httpd.max_body_bytes = int(args.max_body_bytes)  # type: ignore[attr-defined]
    httpd.rl_challenge_ip = TokenBucketLimiter(
        rate_per_s=float(args.rl_challenge_rps), burst=float(args.rl_challenge_burst)
    )  # type: ignore[attr-defined]
    httpd.rl_verify_ip = TokenBucketLimiter(
        rate_per_s=float(args.rl_verify_rps), burst=float(args.rl_verify_burst)
    )  # type: ignore[attr-defined]
    httpd.rl_receive_ip = TokenBucketLimiter(
        rate_per_s=float(args.rl_receive_rps), burst=float(args.rl_receive_burst)
    )  # type: ignore[attr-defined]
    return httpd, node


def main() -> int:
    ap = get_node_argparser()
    args = ap.parse_args()
    httpd, node = build_server_from_args(args)

    if isinstance(node, FieldBoundNodeV3):
        print(
            f"[hive_v3_node_server] node_id={node.node_id} proto={node.profile.protocol_version} "
            f"port={args.port} bundle_id={node.profile.bundle_id.hex()}"
        )
    else:
        print(
            f"[hive_v12_node_server] node_id={node.node_id} seed={node.seed} port={args.port} "
            f"planes={args.planes} tau_frac={args.tau_frac} backend={args.backend}"
        )

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        httpd.server_close()
        if isinstance(node, FieldBoundNodeV3):
            node.close()


if __name__ == "__main__":
    raise SystemExit(main())
