"""
IDRE UDP Gatekeeper — Dark Mode Single Packet Authorization.

Drops ALL traffic by default. Only forwards packets to the Hive node
after the sender proves knowledge of the field configuration via a
cryptographic knock (see knock.py).

Architecture:
  [Internet] → [UDP Gatekeeper :public_port] → [Hive HTTP Server :localhost]
                      ↑ drops unknown
                      ↑ validates knock → adds to allowlist
                      ↑ forwards valid traffic from allowed IPs
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Dict, List, Optional, Set, Tuple

from .knock import verify_knock, KNOCK_LEN

logger = logging.getLogger(__name__)


class UDPGatekeeper:
    """UDP proxy with Single Packet Authorization.
    
    - Listens on a public UDP port
    - Drops all packets from unknown IPs (appears as closed port)
    - Validates knock packets to add IPs to the allowlist
    - Forwards traffic from allowed IPs to the Hive node
    """

    def __init__(
        self,
        *,
        listen_host: str = "0.0.0.0",
        listen_port: int = 9000,
        forward_host: str = "127.0.0.1",
        forward_port: int = 8890,
        secret_bits: List[int],
        ttl_s: float = 60.0,
        max_allowed: int = 1024,
        skew_ms: int = 30_000,
        knock_rate: float = 1.0,
        knock_burst: int = 5,
    ):
        self.listen_host = listen_host
        self.listen_port = int(listen_port)
        self.forward_host = forward_host
        self.forward_port = int(forward_port)
        self.secret_bits = list(secret_bits)
        self.ttl_s = float(ttl_s)
        self.max_allowed = int(max_allowed)
        self.skew_ms = int(skew_ms)
        self.knock_rate = float(knock_rate)   # tokens per second
        self.knock_burst = int(knock_burst)   # max tokens (burst capacity)

        # Allowlist: addr_key -> expiry_timestamp
        self._allowed: Dict[str, float] = {}
        # Per-IP rate limiter: ip -> (tokens, last_refill_ts)
        self._knock_tokens: Dict[str, Tuple[float, float]] = {}
        # Nonce replay window: set of recent nonces
        self._seen_nonces: Set[bytes] = set()
        self._nonce_cleanup_ts: float = 0.0

        # Stats
        self.stats = {
            "knocks_accepted": 0,
            "knocks_rejected": 0,
            "knocks_rate_limited": 0,
            "packets_forwarded": 0,
            "packets_dropped": 0,
        }

        self._transport: Optional[asyncio.DatagramTransport] = None
        self._protocol: Optional[_GatekeeperProtocol] = None

    def _addr_key(self, addr: Tuple[str, int]) -> str:
        return f"{addr[0]}:{addr[1]}"

    def _sweep_expired(self, now: float) -> None:
        """Remove expired entries from allowlist, nonce set, and stale rate-limit buckets."""
        expired = [k for k, exp in self._allowed.items() if exp < now]
        for k in expired:
            del self._allowed[k]

        # Clean nonce set periodically (every 60s)
        if now - self._nonce_cleanup_ts > 60.0:
            self._seen_nonces.clear()
            self._nonce_cleanup_ts = now
            # Also prune stale rate-limit entries (IPs we haven't seen in >60s)
            stale = [ip for ip, (_, ts) in self._knock_tokens.items() if now - ts > 60.0]
            for ip in stale:
                del self._knock_tokens[ip]

    def is_allowed(self, addr: Tuple[str, int]) -> bool:
        """Check if an address is on the allowlist."""
        now = time.time()
        key = self._addr_key(addr)
        exp = self._allowed.get(key)
        if exp is not None and exp >= now:
            return True
        return False

    def handle_packet(
        self, data: bytes, addr: Tuple[str, int]
    ) -> Tuple[str, bool]:
        """Process an incoming packet.
        
        Returns:
            (action, should_forward) where action is one of:
            "knock_accepted", "knock_rejected:reason", "forwarded", "dropped"
        """
        now = time.time()
        self._sweep_expired(now)
        key = self._addr_key(addr)

        # If already allowed, forward
        if key in self._allowed and self._allowed[key] >= now:
            # Refresh TTL on activity
            self._allowed[key] = now + self.ttl_s
            self.stats["packets_forwarded"] += 1
            return "forwarded", True

        # Check if this is a knock packet
        if len(data) == KNOCK_LEN:
            # Rate-limit BEFORE crypto — prevents DoS via knock floods
            ip = addr[0]
            if not self._try_consume_token(ip, now):
                self.stats["knocks_rate_limited"] += 1
                return "knock_rejected:rate_limited", False

            # Extract nonce for replay check
            nonce_bytes = data[15:23]
            if nonce_bytes in self._seen_nonces:
                self.stats["knocks_rejected"] += 1
                return "knock_rejected:replay", False

            valid, reason = verify_knock(
                data, self.secret_bits, skew_ms=self.skew_ms
            )

            if valid:
                # Enforce max allowlist size
                if len(self._allowed) >= self.max_allowed:
                    self._sweep_expired(now)
                    if len(self._allowed) >= self.max_allowed:
                        # Evict oldest
                        oldest_key = min(self._allowed, key=self._allowed.get)  # type: ignore
                        del self._allowed[oldest_key]

                self._allowed[key] = now + self.ttl_s
                self._seen_nonces.add(nonce_bytes)
                self.stats["knocks_accepted"] += 1
                logger.info("Knock accepted from %s", key)
                return "knock_accepted", False
            else:
                self.stats["knocks_rejected"] += 1
                return f"knock_rejected:{reason}", False

        # Unknown packet from unknown IP — drop silently
        self.stats["packets_dropped"] += 1
        return "dropped", False

    def _try_consume_token(self, ip: str, now: float) -> bool:
        """Token bucket rate limiter. Returns True if the request is allowed."""
        if ip in self._knock_tokens:
            tokens, last_ts = self._knock_tokens[ip]
            # Refill tokens based on elapsed time
            elapsed = now - last_ts
            tokens = min(float(self.knock_burst), tokens + elapsed * self.knock_rate)
        else:
            tokens = float(self.knock_burst)

        if tokens < 1.0:
            self._knock_tokens[ip] = (tokens, now)
            return False

        self._knock_tokens[ip] = (tokens - 1.0, now)
        return True

    async def start(self) -> None:
        """Start the UDP gatekeeper server."""
        loop = asyncio.get_event_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _GatekeeperProtocol(self),
            local_addr=(self.listen_host, self.listen_port),
        )
        self._transport = transport
        self._protocol = protocol
        logger.info(
            "Gatekeeper listening on %s:%d → forwarding to %s:%d",
            self.listen_host, self.listen_port,
            self.forward_host, self.forward_port,
        )

    def stop(self) -> None:
        """Stop the gatekeeper."""
        if self._transport:
            self._transport.close()
            self._transport = None


class _GatekeeperProtocol(asyncio.DatagramProtocol):
    """Asyncio protocol handler for the gatekeeper."""

    def __init__(self, gatekeeper: UDPGatekeeper):
        self.gk = gatekeeper

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        action, should_forward = self.gk.handle_packet(data, addr)

        if should_forward and self.gk._transport:
            # Forward to the Hive node
            self.gk._transport.sendto(
                data, (self.gk.forward_host, self.gk.forward_port)
            )


__all__ = ["UDPGatekeeper"]
