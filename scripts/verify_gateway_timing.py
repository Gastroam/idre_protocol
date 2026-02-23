#!/usr/bin/env python3
"""
Verify Gateway Timing & Traffic Shaping
"""

import time
import asyncio
import numpy as np
import subprocess
import sys

from aiohttp import web

# We spin up a Mock Peer to receive cells and measure arrival times.

RECEIVED_TIMES = []

async def mock_peer_handle_cell(request):
    RECEIVED_TIMES.append(time.time())
    return web.Response(status=204)

async def run_mock_peer(port):
    app = web.Application()
    app.router.add_post("/cell", mock_peer_handle_cell)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    return runner

def calculate_stats(times, expected_hz):
    if len(times) < 2:
        return None
    
    deltas = np.diff(times)
    avg_delta = np.mean(deltas)
    measured_hz = 1.0 / avg_delta
    std_dev = np.std(deltas)
    
    print(f"--- Timing Stats ({len(times)} samples) ---")
    print(f"Expected Hz: {expected_hz}")
    print(f"Measured Hz: {measured_hz:.4f}")
    print(f" Avg Delta : {avg_delta*1000:.2f} ms")
    print(f" Std Dev   : {std_dev*1000:.2f} ms (Jitter)")
    
    return measured_hz, std_dev

async def main(healing_mode="none"):
    peer_port = 9011
    gw_port = 9010
    node_port = 8890 # Fake node loc
    
    # 1. Start Mock Peer
    peer_runner = await run_mock_peer(peer_port)
    print(f"[*] Mock Peer running on :{peer_port}")
    
    # 2. Start Gateway (Subprocess)
    gw_cmd = [
        sys.executable, "scripts/idre_gateway.py",
        "--listen", f"127.0.0.1:{gw_port}",
        "--node", f"http://127.0.0.1:{node_port}",
        "--peer-cell-url", f"http://127.0.0.1:{peer_port}/cell",
        "--tick-hz", "10",
        "--jitter-ms", "50", # Some jitter
        "--print-events"
    ]
    
    print(f"[*] Starting Gateway: {' '.join(gw_cmd)}")
    # Allow stderr to flow to checking console or capture it
    import os
    env = os.environ.copy()
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env['PYTHONPATH'] = root_dir + (os.pathsep + env['PYTHONPATH'] if 'PYTHONPATH' in env else '')
    gw_proc = subprocess.Popen(env=env, cwd=root_dir, gw_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    
    try:
        print("[*] Collecting samples for 5 seconds...")
        await asyncio.sleep(5)
        
        # Check if process is dead
        if gw_proc.poll() is not None:
             print(f"[!] Gateway process died early. Return code: {gw_proc.returncode}")
             print(f"[!] Stderr: {gw_proc.stderr.read() if gw_proc.stderr else 'No stderr'}")
             sys.exit(1)

        # Analyze
        stats = calculate_stats(RECEIVED_TIMES, 10.0)
        
        # Always print stderr to check for warnings
        gw_proc.terminate()
        try:
             _, err = gw_proc.communicate(timeout=2)
             if err:
                 print(f"[!] Gateway Stderr:\n{err}")
        except Exception:
             pass

        if not stats:
             print("[!] No packets received (stats=None). Gateway failed to connect?")
             sys.exit(1)
        
        hz, jitter = stats
        # Hz should be close to 10 (allow 10% error due to startup/jitter)
        # Jitter should be non-zero but bounded
        
        if 9.0 < hz < 11.0:
            print("[PASS] Hz is within acceptable range.")
        else:
            print("[FAIL] Hz drifted too much.")
            sys.exit(1)
            
        if jitter > 0.001:
             print("[PASS] Jitter detected (Traffic Shaping active).")
        else:
             print("[WARN] No jitter detected?")
             
    finally:
        print("[*] Cleaning up...")
        gw_proc.terminate()
        gw_proc.wait()
        await peer_runner.cleanup()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--healing-mode", default="none", help="Enable Resonant Multiverse healing")
    args = parser.parse_args()
    
    # Pass args to main (hacky global or param)
    # We'll just change main to accept args or parse inside main.
    # But main is async.
    # Let's just set a global or modify main signature.
    # Modifying main signature is cleanest.
    asyncio.run(main(healing_mode=args.healing_mode))
