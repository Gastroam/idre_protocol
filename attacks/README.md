# IDRE Attack Suite (HTTP)

This suite treats the IDRE nodes as black boxes and attacks the HTTP surface without needing any keys.

It is meant to answer:
- What breaks delivery (DoS) vs what breaks confidentiality (should be impossible without the field).
- What mutations are correctly detected as tamper (`corrupt`) vs accepted.
- Whether header tampering is authenticated (it should be).

## Run

Start nodes (example):

```powershell
python scripts\hive_v12_node_server.py --port 8890 --node-id A --seed 7245 --anchor-seeds 7245 --pepper test_pepper --freeze-field --print-events
python scripts\hive_v12_node_server.py --port 8891 --node-id B --seed 7245 --anchor-seeds 7245 --pepper test_pepper --freeze-field --print-deliveries --print-events
python scripts\hive_v12_node_server.py --port 8892 --node-id EVE --seed 8888 --anchor-seeds 8888 --pepper test_pepper --freeze-field --print-events
```

Run the suite:

```powershell
python attacks\idre_http_attack_suite.py --node-a http://127.0.0.1:8890 --node-b http://127.0.0.1:8891 --node-e http://127.0.0.1:8892
```

It writes a JSON report under `logs/`.

## Cryptanalysis Suite (Permute-XOR Testing)

A dedicated suite for Chosen-Plaintext Attacks (CPA) and empirical randomness testing of the custom IDRE Permute-XOR cipher.

```powershell
python attacks\cryptanalysis\main.py
```

This suite treats the cipher mathematically and tests for cryptographic strength:
- **`collect.py`**: Interacts with the live node to gather thousands of controlled ciphertexts (uniform bytes, counters, random combinations).
- **`stats.py`**: NIST randomness validations (Monobit, Runs, Autocorrelation) and Chi-Square uniform distribution checks.
- **`differential.py`**: Computes Hamming distance avalanche metrics exactly across identical plaintexts.
- **`keystream.py` & `permutation.py`**: Proves CPA resistance against keystream recovery and permutation matrix unmasking.
- **`ml.py`**: Extends validation by training a Scikit-Learn Random Forest model to distinguish the extracted keystreams against `os.urandom()` true hardware noise.

## Extra Suites

Gateway smoke test (spawns 2 nodes + 2 gateways locally, then delivers a message through fixed-size cells):

```powershell
python attacks\idre_gateway_smoke.py
```

Restart/reconnect adversary suite (spawns its own nodes on ephemeral ports):

```powershell
python attacks\idre_restart_reconnect_suite.py
```

Rate limit suite (spawns its own node and hammers handshake endpoints):

```powershell
python attacks\idre_rate_limit_suite.py
```

Slow checks (challenge expiry + session TTL expiry) for the HTTP suite:

```powershell
python attacks\idre_http_attack_suite.py --node-a http://127.0.0.1:8890 --node-b http://127.0.0.1:8891 --node-e http://127.0.0.1:8892 --slow
```

Vocab timing harness (spawns A/B on ephemeral ports and measures handshake/send/receive timings):

```powershell
python attacks\idre_vocab_timing_test.py --codec vocab --vocab-file F:\idre_clean\vocab.bin --no-allow-literals
```
