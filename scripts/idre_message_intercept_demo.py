#!/usr/bin/env python3
"""IDRE demo: encrypt -> intercept -> decrypt attempts.

Uses dedicated endpoints:
- POST /api/idre/send
- POST /api/idre/receive

We pack plaintext into one 256-byte semantic block:
- 2-byte big-endian length
- UTF-8 bytes
- zero padding
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import time
import urllib.request
from typing import Any


def post(url: str, payload: dict[str, Any], timeout: int = 120) -> tuple[int, dict[str, Any]]:
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.getcode(), json.loads(r.read().decode('utf-8'))


def pack_message(msg: str) -> list[int]:
    b = msg.encode('utf-8')
    if len(b) > 254:
        raise ValueError(f'message too long: {len(b)} bytes (max 254)')
    out = bytearray(256)
    out[0] = (len(b) >> 8) & 0xFF
    out[1] = len(b) & 0xFF
    out[2:2+len(b)] = b
    return [x for x in out]


def unpack_message(indices: list[int]) -> str:
    if len(indices) != 256:
        raise ValueError('decoded_indices must be 256')
    n = ((indices[0] & 0xFF) << 8) | (indices[1] & 0xFF)
    raw = bytes((x & 0xFF) for x in indices[2:2+n])
    return raw.decode('utf-8', errors='replace')


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--node-a', default='http://127.0.0.1:8870')
    ap.add_argument('--node-b', default='http://127.0.0.1:8871')
    ap.add_argument('--message', default='Meet at 0300Z. Contract TV0001.')
    ap.add_argument('--counter', type=int, default=1)
    args = ap.parse_args()

    state = {
        'seed': 7245,
        'plane_id': 'covenant',
        'tau': 0.7,
        'epoch': 2,
        # demo digest; for production this must reflect pinned field state
        'state_digest': hashlib.sha256(b'demo-field-state').hexdigest(),
    }

    session_id_hex = 'aa' * 16
    sender_id_hex = 'bb' * 16

    indices = pack_message(args.message)

    # 1) SEND
    send_payload = {
        'state': state,
        'semantic_indices': indices,
        'encode_ctx': {
            'session_id': session_id_hex,
            'sender_id': sender_id_hex,
            'counter': args.counter,
            'private_key_seed': 'alice',
        },
    }
    sc, sb = post(args.node_a.rstrip('/') + '/api/idre/send', send_payload)
    if sc != 200 or sb.get('status') != 'ok':
        raise SystemExit({'send_code': sc, 'send_body': sb})

    packet_b64 = sb['packet_b64']
    packet_bytes = base64.b64decode(packet_b64.encode('ascii'))
    intercept_sha = hashlib.sha256(packet_bytes).hexdigest()

    # 2) ATTACK: missing trust_store
    missing = None
    try:
        missing = post(args.node_b.rstrip('/') + '/api/idre/receive', {'state': state, 'packet_b64': packet_b64, 'decode_ctx': {}})
    except Exception as exc:
        missing = ('error', str(exc))

    # 3) ATTACK: wrong key
    wrong_key = '11' * 32
    wc, wb = post(
        args.node_b.rstrip('/') + '/api/idre/receive',
        {
            'state': state,
            'packet_b64': packet_b64,
            'decode_ctx': {
                'trust_store': {sender_id_hex: wrong_key},
                'expected_session_id': session_id_hex,
                'expected_sender_id': sender_id_hex,
            },
        },
    )

    # 4) RECEIVE: correct key
    pub_hex = sb['public_key_hex']
    rc, rb = post(
        args.node_b.rstrip('/') + '/api/idre/receive',
        {
            'state': state,
            'packet_b64': packet_b64,
            'decode_ctx': {
                'trust_store': {sender_id_hex: pub_hex},
                'expected_session_id': session_id_hex,
                'expected_sender_id': sender_id_hex,
                'expected_indices': indices,
            },
        },
    )

    decrypted = unpack_message(rb.get('decoded_indices', [0] * 256)) if rb.get('decode_status') == 'ok' else None

    # 5) REPLAY
    r2c, r2b = post(
        args.node_b.rstrip('/') + '/api/idre/receive',
        {
            'state': state,
            'packet_b64': packet_b64,
            'decode_ctx': {
                'trust_store': {sender_id_hex: pub_hex},
                'expected_session_id': session_id_hex,
                'expected_sender_id': sender_id_hex,
                'expected_indices': indices,
            },
        },
    )

    out = {
        'ts': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'node_a': args.node_a,
        'node_b': args.node_b,
        'message': args.message,
        'send': {'code': sc, 'body': sb},
        'intercept': {
            'packet_len': len(packet_bytes),
            'packet_sha256': intercept_sha,
            'packet_b64_prefix': packet_b64[:80] + '...'
        },
        'attack_missing_trust': missing,
        'attack_wrong_key': {'code': wc, 'decode_status': wb.get('decode_status')},
        'receive_ok': {'code': rc, 'decode_status': rb.get('decode_status'), 'confidence': rb.get('confidence')},
        'decrypted_message': decrypted,
        'replay': {'code': r2c, 'decode_status': r2b.get('decode_status')},
    }

    print('SEND_OK', sc == 200 and sb.get('status') == 'ok')
    print('INTERCEPT sha256', intercept_sha)
    print('WRONG_KEY decode_status', out['attack_wrong_key']['decode_status'])
    print('OK decode_status', out['receive_ok']['decode_status'])
    print('DECRYPTED', decrypted)
    print('REPLAY decode_status', out['replay']['decode_status'])

    path = 'logs/idre_message_intercept_%d.json' % int(time.time())
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(out, f, indent=2)
    print('WROTE', path)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
