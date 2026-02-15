#!/usr/bin/env python3
"""
IDRE Gateway (Cover Traffic + Fixed-Size Cells)

This is the Internet-facing component for metadata resistance:
  [Internet] <-(Tor/I2P HTTP tunnel)-> [Gateway] <-(localhost)-> [IDRE node]

Responsibilities:
- Maintain a constant-rate stream of fixed-size cells to a peer gateway.
- Carry real IDRE traffic inside cells; send dummy cells when idle.
- Never expose the IDRE node directly to the Internet.

Transport notes:
- This gateway uses HTTP POST for simplicity (plays well with Tor/I2P tunnels).
- Cells are fixed-size blobs; the receiver gateway unpacks and forwards to the local node via /hive/v12/receive_wire.
"""

from __future__ import annotations

import argparse
import json
import queue
import random
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Optional, Tuple

# Allow running as a script from within the standalone package folder:
# repo root is the `idre_clean` package directory; add its parent for imports.
import sys
from pathlib import Path

_REPO_PARENT = str(Path(__file__).resolve().parents[2])
if _REPO_PARENT not in sys.path:
    sys.path.insert(0, _REPO_PARENT)

from idre_clean.core.cell import pack_cell, unpack_cell
from idre_clean.core.wire_bin import pack_receive_envelope, unpack_receive_envelope, unpack_wire_message


DEFAULT_CELL_LEN = 1024
DEFAULT_TICK_HZ = 10.0


def _post_json(url: str, payload: dict, *, timeout: float = 10.0) -> Tuple[int, bytes]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return int(r.getcode()), r.read()
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read()
    except Exception:
        return 0, b""


def _post_bin(url: str, body: bytes, *, timeout: float = 10.0) -> Tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/octet-stream"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return int(r.getcode()), r.read()
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read()
    except Exception:
        return 0, b""


class _ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class Gateway:
    def __init__(
        self,
        *,
        node_base: str,
        peer_cell_url: str,
        cell_len: int,
        tick_hz: float,
        jitter_ms: int,
        rng_seed: int,
        print_events: bool,
    ):
        self.node_base = node_base.rstrip("/")
        self.peer_cell_url = peer_cell_url
        self.cell_len = int(cell_len)
        self.tick_hz = float(tick_hz)
        self.jitter_ms = int(jitter_ms)
        self.print_events = bool(print_events)
        self._rng = random.Random(int(rng_seed))

        self._lock = threading.Lock()
        self._queue: list[bytes] = []
        self._send_q: "queue.Queue[bytes]" = queue.Queue(maxsize=256)
        self._ingest_q: "queue.Queue[bytes]" = queue.Queue(maxsize=4096)
        self._stop = False

    def enqueue_from_node(self, *, dst_node_id: str, content: str) -> bool:
        """
        Ask the local node to build an IDRE message and enqueue it for transmission.
        This requires that the node already has a valid session for dst_node_id.
        """
        code, blob = _post_json(
            self.node_base + "/hive/v12/send_wire",
            {"dst_node_id": str(dst_node_id), "content": str(content), "pad_bytes": 0},
            timeout=20.0,
        )
        if code != 200 or not blob:
            if self.print_events:
                print(f"[gw] enqueue failed code={code}")
            return False
        # send_wire returns packed msg; we wrap into a receive envelope with prev_hop_id=src_node_id.
        try:
            msg = unpack_wire_message(blob)
            prev_hop_id = str(msg.get("src_node_id", ""))
            env = pack_receive_envelope(prev_hop_id, msg)
        except Exception:
            if self.print_events:
                print("[gw] enqueue failed: bad_wire_from_node")
            return False
        with self._lock:
            self._queue.append(env)
        return True

    def _next_cell(self) -> bytes:
        with self._lock:
            inner = self._queue.pop(0) if self._queue else b""
        return pack_cell(inner=inner, cell_len=self.cell_len)

    def tick_loop(self) -> None:
        """Produce fixed-size cells at a constant rate and enqueue for network send.

        This loop must not block on network I/O; it only schedules cell creation.
        """
        hz = max(0.1, float(self.tick_hz))
        period = 1.0 / hz
        t0 = time.monotonic()
        n = 0
        while not self._stop:
            target = t0 + (n * period)
            now = time.monotonic()
            if now < target:
                time.sleep(target - now)
            if self.jitter_ms > 0:
                time.sleep(self._rng.random() * (float(self.jitter_ms) / 1000.0))

            cell = self._next_cell()
            try:
                self._send_q.put_nowait(cell)
            except queue.Full:
                # If the network is slower than our tick rate, drop oldest pending sends.
                # Cover traffic is still attempted at a constant rate; the real network
                # may not sustain it, but we avoid blocking the scheduler.
                try:
                    _ = self._send_q.get_nowait()
                except queue.Empty:
                    pass
                try:
                    self._send_q.put_nowait(cell)
                except queue.Full:
                    pass
            n += 1

    def net_sender_loop(self) -> None:
        """Send cells over the network. Decoupled from scheduling to avoid tick stalls."""
        while not self._stop:
            try:
                cell = self._send_q.get(timeout=0.25)
            except queue.Empty:
                continue
            code, _ = _post_bin(self.peer_cell_url, cell, timeout=5.0)
            if self.print_events and code not in (200, 204, 0):
                print(f"[gw] send cell code={code}")

    def stop(self) -> None:
        self._stop = True

    def ingest_loop(self) -> None:
        """Forward received receive-envelopes to the local node asynchronously.

        Keep network-facing handler timing independent of local node workload.
        """
        while not self._stop:
            try:
                inner = self._ingest_q.get(timeout=0.25)
            except queue.Empty:
                continue
            _post_bin(self.node_base + "/hive/v12/receive_wire", inner, timeout=20.0)

    def handle_incoming_cell(self, blob: bytes) -> None:
        # Drop on parse errors silently. Caller is responsible for response behavior.
        try:
            cell = unpack_cell(blob)
        except Exception:
            return
        if not cell.inner:
            return
        try:
            _prev, _msg = unpack_receive_envelope(cell.inner)
        except Exception:
            return

        try:
            self._ingest_q.put_nowait(cell.inner)
        except queue.Full:
            # Best-effort: drop when overloaded.
            return


class Handler(BaseHTTPRequestHandler):
    server_version = "IDREGateway/0.1"

    def _json(self, code: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _empty(self, code: int):
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        gw: Gateway = self.server.gateway  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0 or length > 10_000_000:
            self._json(400, {"error": "bad_request"})
            return
        raw = self.rfile.read(length)

        if self.path == "/cell":
            # Enforce fixed-size cells. Always respond 204 to avoid an oracle.
            if length != int(gw.cell_len):
                self._empty(204)
                return
            gw.handle_incoming_cell(raw)
            self._empty(204)
            return

        if self.path == "/enqueue":
            try:
                data = json.loads(raw.decode("utf-8"))
            except Exception:
                self._json(400, {"error": "bad_json"})
                return
            dst = str(data.get("dst_node_id", ""))
            content = data.get("content")
            if not dst or not isinstance(content, str):
                self._json(400, {"error": "bad_request"})
                return
            ok = gw.enqueue_from_node(dst_node_id=dst, content=content)
            self._json(200, {"status": "ok", "enqueued": bool(ok)})
            return

        self._json(404, {"error": "not_found"})

    def log_message(self, fmt: str, *args):
        return


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="127.0.0.1:9010", help="host:port for incoming /cell and /enqueue")
    ap.add_argument("--node", default="http://127.0.0.1:8890", help="local node base URL (localhost-only)")
    ap.add_argument("--peer-cell-url", required=True, help="remote gateway cell URL, e.g. http://peer/cell (Tor/I2P tunnel)")
    ap.add_argument("--cell-len", type=int, default=DEFAULT_CELL_LEN)
    ap.add_argument("--tick-hz", type=float, default=DEFAULT_TICK_HZ)
    ap.add_argument("--jitter-ms", type=int, default=150)
    ap.add_argument("--rng-seed", type=int, default=1337)
    ap.add_argument("--print-events", action="store_true")
    args = ap.parse_args()

    host, port_s = str(args.listen).rsplit(":", 1)
    port = int(port_s)

    gw = Gateway(
        node_base=str(args.node),
        peer_cell_url=str(args.peer_cell_url),
        cell_len=int(args.cell_len),
        tick_hz=float(args.tick_hz),
        jitter_ms=int(args.jitter_ms),
        rng_seed=int(args.rng_seed),
        print_events=bool(args.print_events),
    )

    tick = threading.Thread(target=gw.tick_loop, daemon=True)
    net = threading.Thread(target=gw.net_sender_loop, daemon=True)
    ingest = threading.Thread(target=gw.ingest_loop, daemon=True)
    tick.start()
    net.start()
    ingest.start()

    httpd = _ThreadedHTTPServer((str(host), int(port)), Handler)
    httpd.gateway = gw  # type: ignore[attr-defined]
    if gw.print_events:
        print(f"[gw] listen http://{host}:{port}  node={args.node}  peer={args.peer_cell_url}  cell_len={args.cell_len}  tick_hz={args.tick_hz}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        gw.stop()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
