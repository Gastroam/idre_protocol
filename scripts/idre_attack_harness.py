#!/usr/bin/env python3
"""
IDRE dual-node attack harness (local).

Purpose:
- Stress and fuzz MTI-EVO nodes while checking determinism and failure modes.
- Produce a machine-readable report in logs/.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import random
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any


def http_json(url: str, method: str = "GET", payload: dict[str, Any] | None = None, timeout: int = 30) -> tuple[int, dict[str, Any] | str | None, str | None]:
    data = None
    headers = {"Content-Type": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url=url, method=method, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.getcode(), json.loads(raw), None
            except json.JSONDecodeError:
                return resp.getcode(), raw, None
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return exc.code, body, f"http_{exc.code}"
    except urllib.error.URLError as exc:
        return 0, None, f"url_error:{exc.reason}"
    except TimeoutError:
        return 0, None, "timeout"
    except Exception as exc:
        return 0, None, f"error:{type(exc).__name__}:{exc}"


def http_raw_invalid_json(url: str, timeout: int = 15) -> tuple[int, str]:
    req = urllib.request.Request(url=url, method="POST", data=b"{invalid_json", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return exc.code, body
    except Exception as exc:
        return 0, f"error:{type(exc).__name__}:{exc}"


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def build_payload(prompt: str, seed: int, max_tokens: int, temperature: float) -> dict[str, Any]:
    return {
        "action": "raw",
        "prompt": prompt,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "seed": seed,
        "learn": False,
        "symbiosis": False,
        "integer_communication": False,
        "timeout": 120,
    }


def one_probe(base: str, payload: dict[str, Any], timeout: int = 150) -> dict[str, Any]:
    t0 = time.perf_counter()
    code, body, err = http_json(f"{base}/v1/local/reflex", method="POST", payload=payload, timeout=timeout)
    dt_ms = (time.perf_counter() - t0) * 1000.0
    out: dict[str, Any] = {"ok": False, "code": code, "latency_ms": dt_ms, "error": err}
    if isinstance(body, dict) and code == 200 and "response" in body:
        text = str(body.get("response", ""))
        out.update(
            {
                "ok": True,
                "hash": sha(text),
                "tokens": int(body.get("tokens", 0) or 0),
                "resonance": float(body.get("resonance", 0.0) or 0.0),
                "response_len": len(text),
            }
        )
    return out


def check_up(base: str) -> dict[str, Any]:
    s_code, s_body, s_err = http_json(f"{base}/status", timeout=10)
    i_code, i_body, i_err = http_json(f"{base}/api/idre/health", timeout=10)
    return {
        "status_code": s_code,
        "status": s_body if isinstance(s_body, dict) else {"raw": s_body, "err": s_err},
        "idre_code": i_code,
        "idre": i_body if isinstance(i_body, dict) else {"raw": i_body, "err": i_err},
    }


def phase_invalid_json(nodes: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for n in nodes:
        code, body = http_raw_invalid_json(f"{n}/v1/local/reflex", timeout=15)
        out[n] = {"code": code, "body_preview": body[:160]}
    return out


def phase_oversize_prompt(nodes: list[str], size: int, seed: int) -> dict[str, Any]:
    huge = "Q" * size
    payload = build_payload(huge, seed=seed, max_tokens=32, temperature=0.0)
    out: dict[str, Any] = {}
    for n in nodes:
        code, body, err = http_json(f"{n}/v1/local/reflex", method="POST", payload=payload, timeout=180)
        out[n] = {
            "code": code,
            "error": err,
            "keys": sorted(list(body.keys())) if isinstance(body, dict) else None,
        }
    return out


def phase_pair_storm(node_a: str, node_b: str, rounds: int, workers: int, prompt: str, seed: int, max_tokens: int, temperature: float) -> dict[str, Any]:
    payload = build_payload(prompt, seed=seed, max_tokens=max_tokens, temperature=temperature)
    lock = threading.Lock()
    stats = {
        "rounds": rounds,
        "workers": workers,
        "ok_pairs": 0,
        "a_fail": 0,
        "b_fail": 0,
        "hash_match": 0,
        "hash_mismatch": 0,
        "sample_mismatch": [],
    }

    def job(i: int) -> None:
        ra = one_probe(node_a, payload)
        rb = one_probe(node_b, payload)
        with lock:
            if not ra.get("ok"):
                stats["a_fail"] += 1
            if not rb.get("ok"):
                stats["b_fail"] += 1
            if ra.get("ok") and rb.get("ok"):
                stats["ok_pairs"] += 1
                if ra.get("hash") == rb.get("hash"):
                    stats["hash_match"] += 1
                else:
                    stats["hash_mismatch"] += 1
                    if len(stats["sample_mismatch"]) < 5:
                        stats["sample_mismatch"].append({"i": i, "a": ra.get("hash"), "b": rb.get("hash")})

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(job, i) for i in range(rounds)]
        done = 0
        for f in concurrent.futures.as_completed(futs):
            done += 1
            if done % max(1, rounds // 10) == 0:
                print(f"[storm] progress {done}/{rounds}")
            f.result()

    return stats


def phase_replay(node: str, rounds: int, prompt: str, seed: int, max_tokens: int, temperature: float) -> dict[str, Any]:
    payload = build_payload(prompt, seed=seed, max_tokens=max_tokens, temperature=temperature)
    hashes: list[str] = []
    fails = 0
    for i in range(rounds):
        r = one_probe(node, payload)
        if r.get("ok"):
            hashes.append(str(r.get("hash")))
        else:
            fails += 1
        if (i + 1) % max(1, rounds // 5) == 0:
            print(f"[replay:{node}] {i + 1}/{rounds}")
    unique = sorted(set(hashes))
    return {
        "rounds": rounds,
        "fails": fails,
        "unique_hash_count": len(unique),
        "hash_sample": unique[:5],
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Attack harness for dual MTI-EVO nodes.")
    p.add_argument("--node-a", default="http://127.0.0.1:8814")
    p.add_argument("--node-b", default="http://127.0.0.1:8815")
    p.add_argument("--storm-rounds", type=int, default=40)
    p.add_argument("--storm-workers", type=int, default=8)
    p.add_argument("--replay-rounds", type=int, default=20)
    p.add_argument("--oversize-bytes", type=int, default=120000)
    p.add_argument("--seed", type=int, default=424242)
    p.add_argument("--max-tokens", type=int, default=120)
    p.add_argument("--temperature", type=float, default=0.2)
    p.add_argument(
        "--prompt",
        default="Explain in 5 precise bullets how quantum decoherence differs from wavefunction collapse.",
    )
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    node_a = args.node_a.rstrip("/")
    node_b = args.node_b.rstrip("/")

    print("[1/6] baseline health")
    baseline = {node_a: check_up(node_a), node_b: check_up(node_b)}
    print(json.dumps(baseline, indent=2))

    print("[2/6] invalid JSON attack")
    invalid_json = phase_invalid_json([node_a, node_b])
    print(json.dumps(invalid_json, indent=2))

    print("[3/6] oversize prompt attack")
    oversize = phase_oversize_prompt([node_a, node_b], size=args.oversize_bytes, seed=args.seed)
    print(json.dumps(oversize, indent=2))

    print("[4/6] pair storm attack")
    storm = phase_pair_storm(
        node_a=node_a,
        node_b=node_b,
        rounds=args.storm_rounds,
        workers=args.storm_workers,
        prompt=args.prompt,
        seed=args.seed,
        max_tokens=args.max_tokens,
        temperature=args.temperature,
    )
    print(json.dumps(storm, indent=2))

    print("[5/6] replay attack A")
    replay_a = phase_replay(node_a, rounds=args.replay_rounds, prompt=args.prompt, seed=args.seed, max_tokens=args.max_tokens, temperature=args.temperature)
    print(json.dumps(replay_a, indent=2))

    print("[6/6] replay attack B")
    replay_b = phase_replay(node_b, rounds=args.replay_rounds, prompt=args.prompt, seed=args.seed, max_tokens=args.max_tokens, temperature=args.temperature)
    print(json.dumps(replay_b, indent=2))

    report = {
        "timestamp": now(),
        "nodes": [node_a, node_b],
        "config": {
            "storm_rounds": args.storm_rounds,
            "storm_workers": args.storm_workers,
            "replay_rounds": args.replay_rounds,
            "oversize_bytes": args.oversize_bytes,
            "seed": args.seed,
            "max_tokens": args.max_tokens,
            "temperature": args.temperature,
        },
        "baseline": baseline,
        "invalid_json": invalid_json,
        "oversize": oversize,
        "storm": storm,
        "replay": {"node_a": replay_a, "node_b": replay_b},
    }

    os.makedirs("logs", exist_ok=True)
    out_path = os.path.join("logs", f"idre_attack_report_{int(time.time())}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"report={out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
