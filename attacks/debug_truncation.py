import requests

BASE_URL = 'https://idre.mti-evo.online'

print("1. Handshake")
requests.post(f"{BASE_URL}/api/demo/handshake")

print("2. Send")
r_send = requests.post(f"{BASE_URL}/api/demo/send", json={"message": "truncate_me"})
wire_msg = r_send.json()["wire_message"]

# Truncate aggressively to 10 bytes to ensure the MAC is destroyed, not just padding
print(f"Original payload len: {len(wire_msg['payload'])}")
wire_msg["payload"] = wire_msg["payload"][:10]
print(f"Truncated payload len: {len(wire_msg['payload'])}")

print("3. Receive on demo API")
r1 = requests.post(f"{BASE_URL}/api/demo/receive", json={"wire_message": wire_msg})
print("Demo API Response:", r1.status_code, r1.json())

print("4. Receive on raw Node B endpoint")
r2 = requests.post(f"{BASE_URL}/node-b/hive/v12/verify_req/process", json=wire_msg)
print("Raw API Response:", r2.status_code, r2.text)
