"""Legacy Hive v1.2 + IDREStream v2.0 demo (field-bound, no PKI).

This script runs entirely from the backup snapshot under:
  unused/backups/MTI-EVO-v1/

It demonstrates:
- Field-bound identity match (7245 vs 7245)
- Verification challenge establishing sessions
- Hop-by-hop encrypted payload delivery
- Intercept attempts (wrong field, wrong salt)
- Replay rejection (nonce reuse)

Outputs a JSON artifact under logs/.
"""

from __future__ import annotations

import json
import os
import time
import pathlib


def _ts() -> int:
    return int(time.time())


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[1]
    backup_root = root / "unused" / "backups" / "MTI-EVO-v1"

    os.environ.setdefault("PYTHONUTF8", "1")

    # Ensure backup can be imported as a top-level package that contains `src/`.
    import sys

    sys.path.insert(0, str(backup_root))

    from src.mti_hive_node import HiveNode  # type: ignore

    # Patch backup defaults so 8888 behaves as an adversarial (non-anchor) field.
    # Otherwise the backup config anchors both (7245, 8888) and can make them identical.
    from src.mti_config import MTIConfig  # type: ignore
    MTIConfig.__dataclass_fields__['idre_anchor_seeds'].default = (7245,)


    out: dict = {
        "timestamp": _ts(),
        "backup_root": str(backup_root),
        "steps": [],
    }

    def step(name: str, **data):
        out["steps"].append({"name": name, "t": _ts(), **data})

    # --- Nodes ---
    alice = HiveNode("ALICE", seed=7245)
    bob = HiveNode("BOB", seed=7245)
    eve = HiveNode("EVE", seed=8888)

    # Force adversary field divergence: compute B for seed 8888 without treating it as an anchor.
    # The legacy config anchors (7245, 8888) which can accidentally make them identical.
    from src.mti_idre import IDREStream  # type: ignore
    adv = IDREStream()
    adv.idre_seeds = (7245,)  # exclude 8888 from anchor initialization
    eve.fingerprint_B = adv.generate_fingerprint_B(8888)
    import hashlib
    eve.field_hash = hashlib.sha256(eve.fingerprint_B.tobytes()).hexdigest()[:16]


    step(
        "node_init",
        alice_field=alice.field_hash,
        bob_field=bob.field_hash,
        eve_field=eve.field_hash,
    )

    # --- HELLO ---
    hello = alice.create_handshake_hello()
    ok_hello = bob.process_handshake_hello(hello)
    step("hello", hello=hello, bob_accept=bool(ok_hello))

    # --- VERIFY (symmetric) ---
    session_id = 424242
    ephemeral_salt = 7777

    chall_ab = alice.create_verification_challenge(session_id=session_id, ephemeral_salt=ephemeral_salt)
    ok_ab = bob.process_verification_challenge(chall_ab, peer_id="ALICE")
    step("verify_ab", req=chall_ab, bob_accept=bool(ok_ab))

    chall_ba = bob.create_verification_challenge(session_id=session_id, ephemeral_salt=ephemeral_salt)
    ok_ba = alice.process_verification_challenge(chall_ba, peer_id="BOB")
    step("verify_ba", req=chall_ba, alice_accept=bool(ok_ba))

    # --- Send message ---
    plaintext = "CONTRACT|PAY=10|CUR=USD|TERM=NET30"
    msg = alice.send_message("BOB", plaintext)
    step("send", message=msg)

    delivered = bob.receive_message(msg, prev_hop_id="ALICE")
    step("deliver", delivered=delivered)

    # --- Intercept attempts ---
    # Attacker sees outer envelope, not the salt. Here we test both 'wrong salt' and 'known salt'.
    payload = msg.get("payload")
    nonce = int(msg.get("nonce", 0))

    try:
        guess0 = eve._decrypt_string(payload, session_id=session_id, nonce=nonce, ephemeral_salt=0)
    except Exception as exc:
        guess0 = f"error:{exc}"

    try:
        knowsalt = eve._decrypt_string(payload, session_id=session_id, nonce=nonce, ephemeral_salt=ephemeral_salt)
    except Exception as exc:
        knowsalt = f"error:{exc}"

    step(
        "intercept",
        eve_guess_ephemeral_0=guess0,
        eve_guess_with_ephemeral=knowsalt,
    )

    # --- Replay ---
    replay = bob.receive_message(msg, prev_hop_id="ALICE")
    step("replay", replay_result=replay)

    ok = delivered == plaintext

    step("result", ok=bool(ok))

    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    out_path = logs_dir / f"legacy_hive_v12_demo_{_ts()}.json"
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")

    print(f"[legacy_hive_v12_demo] wrote {out_path}")
    print(f"[legacy_hive_v12_demo] delivered_ok={ok}")
    if not ok:
        print(f"[legacy_hive_v12_demo] delivered={delivered!r}")

    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())


