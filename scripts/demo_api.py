#!/usr/bin/env python3
"""
IDRE Demo API — Interactive testing wrapper for security researchers.

Runs two HIVE nodes (Alice & Bob) internally and exposes a REST API
that lets researchers see the full encode→encrypt→transmit→decrypt→decode
pipeline, inspect wire format, and test attack vectors.

Usage:
    python demo_api.py --seed 7245 --pepper "demo_pepper_2026"
"""
import sys
import os
import json
import time
import secrets
import warnings
from pathlib import Path

# Suppress pepper warnings for demo nodes (we handle it explicitly)
warnings.filterwarnings("ignore", message="IDRE SECURITY WARNING")

# Fix imports
_REPO_PARENT = str(Path(__file__).resolve().parent.parent.parent)
if _REPO_PARENT not in sys.path:
    sys.path.insert(0, _REPO_PARENT)

from flask import Flask, request, jsonify
from idre_clean.hive.node import FieldBoundNode
from idre_clean.core.vocab_codec import Vocab, load_vocab_registry

app = Flask(__name__)

# --- Globals (initialized in main) ---
node_a: FieldBoundNode = None  # type: ignore
node_b: FieldBoundNode = None  # type: ignore


def _create_demo_vocab():
    """Create a minimal vocab for demo purposes if vocab.jsonl doesn't exist."""
    try:
        registry, vocab = load_vocab_registry(["vocab.jsonl"])
        return vocab, registry
    except Exception:
        # Fallback: create a minimal ASCII vocab
        tokens = [chr(i) for i in range(32, 127)]
        tok_to_idx = {t: i for i, t in enumerate(tokens)}
        vocab_hash = b"demo_vocab_hash_"
        return Vocab(tokens, tok_to_idx, vocab_hash, {}), None


def _init_nodes(seed: int, pepper: str):
    """Initialize Alice and Bob nodes with shared config."""
    global node_a, node_b
    vocab, registry = _create_demo_vocab()

    common = dict(
        seed=seed,
        anchor_seeds=(seed,),
        anchor_weight=80.0,
        n_angles=72,
        scan_resolution=50,
        threshold=0.5,
        planes=4,
        tau_frac=0.55,
        print_deliveries=False,
        print_events=False,
        freeze_field=True,
        backend="frozen",
        pepper=pepper,
        vocab=vocab,
        vocab_registry=registry,
    )

    node_a = FieldBoundNode(node_id="ALICE", **common)
    node_b = FieldBoundNode(node_id="BOB", **common)

    # Establish a session between them using IDRE v1.2 force_session
    session_id = secrets.token_hex(16)
    e_salt = secrets.randbits(64)
    node_a.force_session("BOB", session_id, e_salt)
    node_b.force_session("ALICE", session_id, e_salt)

    print(f"[demo_api] Nodes initialized. Seed={seed}, Pepper={'SET' if pepper else 'NONE'}")
    print(f"[demo_api] Session forced: ALICE <-> BOB (ID={session_id[:8]})")


# ─── CORS helper ─────────────────────────────────────────────────
@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


# ─── Demo Endpoints ──────────────────────────────────────────────

@app.route("/api/demo/status", methods=["GET"])
def demo_status():
    """Health check for both nodes."""
    return jsonify({
        "status": "ok",
        "nodes": {
            "alice": {
                "node_id": node_a.node_id,
                "field_profile_id": node_a.field_profile_id,
                "sessions": len(node_a.timelines),
            },
            "bob": {
                "node_id": node_b.node_id,
                "field_profile_id": node_b.field_profile_id,
                "sessions": len(node_b.timelines),
            }
        },
        "server_time_ms": int(time.time() * 1000),
        "protocol": "HIVE-P2P/1.2",
    })


@app.route("/api/demo/send", methods=["POST"])
def demo_send():
    """
    Encrypt a message from Alice → Bob. Returns the wire format.
    Body: {"message": "hello world"}
    
    Security researchers: the response shows exactly what goes on the wire.
    Try modifying the payload and submitting it to /api/demo/receive.
    """
    data = request.get_json(force=True, silent=True) or {}
    message = str(data.get("message", ""))[:1024]  # Cap at 1KB

    if not message:
        return jsonify({"error": "missing 'message' field"}), 400

    try:
        wire_msg = node_a.send("BOB", message)
        if wire_msg is None:
            return jsonify({"error": "send failed — no active session"}), 500

        return jsonify({
            "status": "encrypted",
            "plaintext_length": len(message),
            "wire_message": wire_msg,
            "wire_size_bytes": len(json.dumps(wire_msg)),
            "note": "This is what goes on the wire. The integers are meaningless without the field configuration.",
            "try_this": "POST this wire_message to /api/demo/receive to see Bob decode it, or modify it first to test tamper detection.",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/demo/receive", methods=["POST"])
def demo_receive():
    """
    Submit a wire message to Bob for decryption.
    Body: {"wire_message": {...}} (the object from /api/demo/send)
    
    Try tampering with the payload before submitting — Bob should reject it.
    """
    data = request.get_json(force=True, silent=True) or {}
    wire_msg = data.get("wire_message")

    if not wire_msg or not isinstance(wire_msg, dict):
        return jsonify({"error": "missing 'wire_message' object"}), 400

    try:
        result = node_b.receive(wire_msg, prev_hop_id="ALICE")
        # Sanitize: never expose raw plaintext to the public API
        safe_result = {
            "status": result.get("status", "unknown"),
            "decrypted_length": len(result.get("plaintext", "")) if result.get("plaintext") else 0,
            "decrypted_preview": result.get("plaintext", "")[:64] + "..." if len(result.get("plaintext", "")) > 64 else result.get("plaintext", ""),
        }
        if result.get("status") != "delivered":
            safe_result["rejection_reason"] = result.get("error", result.get("status", "unknown"))

        return jsonify(safe_result)
    except Exception as e:
        return jsonify({"status": "rejected", "rejection_reason": str(e)}), 200


@app.route("/api/demo/handshake", methods=["POST"])
def demo_handshake():
    """
    Walk through a full challenge/verify handshake between Alice and Bob.
    No body required. Returns all intermediate states.
    """
    try:
        # 1. Alice creates challenge
        pending = node_a.issue_challenge("BOB")
        challenge_id = pending.challenge

        # 2. Bob creates verify request (encrypted signature)
        session_id = secrets.token_hex(16)
        e_salt = secrets.randbits(64)
        verify_req = node_b.create_verify_req(session_id, e_salt, challenge_id)

        # 3. Alice processes and finalizes
        success = node_a.process_verify_req(verify_req, "BOB")

        if not success:
            return jsonify({"error": "handshake failed validation"}), 400

        # After Alice processes, we MUST force both nodes into identical simulated states.
        # process_verify_req uses `genesis_chain_hash` while `force_session` uses
        # `forced_chain_hash`, leading to MAC failures if they mismatch.
        node_a.force_session("BOB", session_id, e_salt)
        node_b.force_session("ALICE", session_id, e_salt)

        return jsonify({
            "status": "handshake_complete",
            "steps": [
                {"step": 1, "action": "Alice issues challenge", "data": {"challenge_id": challenge_id}},
                {"step": 2, "action": "Bob creates verify_req", "data": {"session_id": session_id, "nonce": verify_req["nonce"]}},
                {"step": 3, "action": "Alice processes verify_req", "result": "session_established"},
            ],
            "note": "A new session is now active. Previous session was replaced.",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/demo/fingerprint", methods=["GET"])
def demo_fingerprint():
    """
    Show the public fingerprint bits for both nodes.
    This is safe to share — it's what an attacker would observe.
    The pepper (if set) means these bits can't be used for weight recovery.
    """
    bits_a = node_a.fingerprint_bits(node_a.seed)
    bits_b = node_b.fingerprint_bits(node_b.seed)

    return jsonify({
        "alice": {
            "fingerprint_bits": bits_a,
            "bit_count": len(bits_a),
            "ones_ratio": sum(bits_a) / len(bits_a) if bits_a else 0,
        },
        "bob": {
            "fingerprint_bits": bits_b,
            "bit_count": len(bits_b),
            "ones_ratio": sum(bits_b) / len(bits_b) if bits_b else 0,
        },
        "match": bits_a == bits_b,
        "note": "Both nodes produce identical fingerprint bits from the same seed. "
                "With pepper active, gradient-descent recovery is blocked (see paper §2.2, Appendix A.3).",
    })


@app.route("/api/demo/config", methods=["GET"])
def demo_config():
    """
    Show the non-secret configuration parameters.
    Researchers: this is what you know as an attacker. Can you break it?
    """
    return jsonify({
        "public_parameters": {
            "n_angles": node_a.n_angles,
            "scan_resolution": node_a.scan_resolution,
            "planes": node_a.planes,
            "tau_frac": node_a.tau_frac,
            "embedding_dim": node_a.embedding_dim,
            "threshold": node_a.threshold,
            "backend": node_a.backend,
        },
        "secret_parameters": {
            "seed": "REDACTED — this is the field geometry generator",
            "pepper": "REDACTED — HMAC trapdoor key",
            "topology_seed": "REDACTED — Ghost Topology folding matrix",
            "vocabulary": "REDACTED — network-sovereign tokenizer",
        },
        "challenge": "Given the public parameters and intercepted wire messages, "
                     "can you recover the plaintext? See /api/demo/send to generate traffic.",
    })


# --- Auto-initialize when imported by gunicorn ---
# Set IDRE_SEED and IDRE_PEPPER env vars, or use defaults
if node_a is None:
    _seed = int(os.environ.get("IDRE_SEED", "7245"))
    _pepper = os.environ.get("IDRE_PEPPER", "idre_demo_pepper_2026_ec2")
    _init_nodes(seed=_seed, pepper=_pepper)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="IDRE Demo API")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--seed", type=int, default=7245)
    ap.add_argument("--pepper", type=str, default="idre_demo_pepper_2026")
    ap.add_argument("--host", type=str, default="127.0.0.1")
    args = ap.parse_args()

    _init_nodes(seed=args.seed, pepper=args.pepper)
    app.run(host=args.host, port=args.port, debug=False)
