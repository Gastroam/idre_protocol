import requests

BASE_URL = 'https://idre.mti-evo.online'

print("1. Handshake")
r = requests.post(f"{BASE_URL}/api/demo/handshake")
print(r.json())

print("2. Send")
r_send = requests.post(f"{BASE_URL}/api/demo/send", json={"message": "replay_me"})
wire_msg = r_send.json()["wire_message"]
print(wire_msg["session_id"], wire_msg["nonce"])

print("3. Receive")
r1 = requests.post(f"{BASE_URL}/api/demo/receive", json={"wire_message": wire_msg})
print(r1.json())
