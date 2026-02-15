# Future: Dark Mode & Gatekeeper

## Concept
"Dark Mode" aims to make the node invisible to unauthorized probes. It uses a "Gatekeeper" (UDP Proxy) and a cryptographic "Knock" sequence.

## Components

### 1. Gatekeeper (UDP Proxy)
- **Role**: Validates "Knock" packets before forwarding traffic to the Hive Node.
- **Mechanism**:
    - Listens on public UDP port.
    - Drops all packets by default (Allowlist = Empty).
    - Checks for `KNOCK` signature (HMAC of timestamp + nonce).
    - If valid, adds Source IP to allowlist for `N` seconds.
    - Forwards valid protocol traffic to localhost Hive Node.

### 2. Client Knock
- **Role**: Clients send a recursive sequence of packets to "wake up" the Gatekeeper.
- **Sequence**:
    1. `HELLO` (ignored/dropped)
    2. `KNOCK` (validates IP)
    3. `HANDSHAKE` (forwarded to Node)

## Implementation Plan
### 1. `hive/gatekeeper.py`
- **Class**: `UDPGatekeeper`
    - `__init__(listen_ip, listen_port, forward_ip, forward_port, secret)`
    - `start()`: Asyncio/Threaded UDP socket loop.
    - `_handle_packet(data, addr)`:
        - If `addr` in `allowed_ips`: Forward to `forward_addr`.
        - Else: Check if `data` is a valid Knock (HMAC verification).
            - If valid: Add to `allowed_ips`.
            - Else: Drop silently.

### 2. `hive/client.py`
- **Method**: `send_knock(target_ip, target_port, secret)`
- **Flow**:
    1. Send Knock Packet.
    2. Wait (short delay).
    3. Send actual Handshake/Data.

## Verification
- **Automated Test**: `tests/test_dark_mode.py`
    - Scenario A: Unauth -> Explicit Timeout/Drop.
    - Scenario B: Auth -> Success.
