"""End-to-end live HTTP + CLI wiring tests for IDRE v3."""

from __future__ import annotations

import json
import threading
from pathlib import Path

from core.profile_v3 import compute_vocab_digest_v3
from core.vocab_codec import load_vocab
from hive.cli import configure_node_from_args, get_node_argparser
from hive.client_v3 import HiveClientV3
from hive.node_v3 import FieldBoundNodeV3
from hive.server_v3 import create_server_v3


def _build_node_via_cli(tmp_path: Path, node_id: str, vocab_path: Path, vocab_digest_hex: str) -> FieldBoundNodeV3:
    ap = get_node_argparser()
    args = ap.parse_args(
        [
            "--protocol-version",
            "v3",
            "--node-id",
            node_id,
            "--backend",
            "lattice",
            "--enable-plasticity",
            "--content-codec",
            "vocab",
            "--no-vocab-allow-literals",
            "--max-plaintext-bytes",
            "4023",
            "--vocab-file",
            str(vocab_path),
            "--state-db",
            str(tmp_path / f"{node_id}.sqlite"),
            "--bundle-id-hex",
            "aa" * 16,
            "--expected-vocab-digest-hex",
            vocab_digest_hex,
            "--network-secret-hex",
            "11" * 32,
            "--field-init-secret-hex",
            "22" * 32,
            "--storage-key-hex",
            ("33" if node_id == "A" else "44") * 32,
            "--adaptive-codec",
        ]
    )
    # Remove default "vocab.jsonl" injected by argparse append default
    args.vocab_file = [str(vocab_path)]
    node = configure_node_from_args(args)
    assert isinstance(node, FieldBoundNodeV3)
    return node


def test_live_http_v3_cli_handshake_send_retry_and_ack(tmp_path: Path):
    vocab_path = tmp_path / "vocab.json"
    vocab_path.write_text(json.dumps(["red", "blue", "green", " "]), encoding="utf-8")
    digest_hex = compute_vocab_digest_v3(load_vocab(str(vocab_path))).hex()

    node_a = _build_node_via_cli(tmp_path, "A", vocab_path, digest_hex)
    node_b = _build_node_via_cli(tmp_path, "B", vocab_path, digest_hex)

    srv_a = create_server_v3(node_a, host="127.0.0.1", port=0)
    srv_b = create_server_v3(node_b, host="127.0.0.1", port=0)
    t_a = threading.Thread(target=srv_a.serve_forever, daemon=True)
    t_b = threading.Thread(target=srv_b.serve_forever, daemon=True)
    t_a.start()
    t_b.start()

    try:
        client_a = HiveClientV3(f"http://127.0.0.1:{srv_a.server_address[1]}")
        client_b = HiveClientV3(f"http://127.0.0.1:{srv_b.server_address[1]}")

        assert client_a.health()["proto"] == "IDRE/3.0"
        hello_b = client_b.hello()
        assert hello_b["node_id"] == "B"
        assert "expected_vocab_digest" not in hello_b

        # 1. Real mutual v3 handshake over HTTP
        sid_hex = client_a.mutual_handshake(client_b, initiator_id="A", responder_id="B")
        assert len(bytes.fromhex(sid_hex)) == 16

        # 2. Send DATA over HTTP, simulate lost ACK, retransmit exact bytes, then deliver ACK
        c_send, r_send = client_a.send("B", "red blue")
        assert c_send == 200
        pkt_hex = r_send["packet_hex"]

        # Retransmit returns exact identical stored bytes
        assert client_a.retransmit("B") == pkt_hex

        # First receive delivers
        c_rx1, r_rx1 = client_b.receive("A", pkt_hex)
        assert c_rx1 == 200 and r_rx1["status"] == "delivered"

        # Exact duplicate receive returns cached ACK without duplicate inbox row
        c_rx2, r_rx2 = client_b.receive("A", pkt_hex)
        assert c_rx2 == 200 and r_rx2["status"] == "duplicate"
        assert r_rx2["ack_hex"] == r_rx1["ack_hex"]

        # Apply ACK on A -> resolves pending send
        c_ack, r_ack = client_a.ack("B", r_rx2["ack_hex"])
        assert c_ack == 200 and r_ack["status"] == "acked"
        assert r_ack["new_next_seq"] == 1
        assert r_ack["new_field_age"] == 1
        assert client_a.retransmit("B") is None

        # Verify durable inbox on B has exactly 1 record
        inbox = client_b.inbox("A")
        assert len(inbox) == 1
        assert inbox[0]["plaintext"] == "red blue"
    finally:
        srv_a.shutdown()
        srv_b.shutdown()
        srv_a.server_close()
        srv_b.server_close()
        node_a.close()
        node_b.close()
