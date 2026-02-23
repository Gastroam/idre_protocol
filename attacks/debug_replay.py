import sys

try:
    from scripts import demo_api
except Exception as e:
    print("Import error:", e)

import secrets

session_id = secrets.token_hex(16)
e_salt = secrets.randbits(64)
demo_api.node_a.force_session("BOB", session_id, e_salt)
demo_api.node_b.force_session("ALICE", session_id, e_salt)
sa = demo_api.node_a.sessions.get("BOB")
sb = demo_api.node_b.sessions.get("ALICE")

print("Alice Sess:", sa.session_id if sa else None, "out_seq:", sa.out_seq if sa else None, "in_seq:", sa.in_seq if sa else None)
print("Bob Sess:  ", sb.session_id if sb else None, "out_seq:", sb.out_seq if sb else None, "in_seq:", sb.in_seq if sb else None)
if sa and sb:
    print("Alice Chain Hash:", sa.chain_hash.hex())
    print("Bob Chain Hash:  ", sb.chain_hash.hex())
    print("Alice Ratchet Key:", str(sa.ratchet_key)[:16])
    print("Bob Ratchet Key:  ", str(sb.ratchet_key)[:16])

res = demo_api.node_a.send("BOB", "hello")
print("\nAlice out_seq after send:", sa.out_seq)
print("Alice chain_hash after send:", sa.chain_hash.hex())

recv_res = demo_api.node_b.receive(res, "ALICE")
print("Bob receive result:", recv_res)
