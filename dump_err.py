import subprocess
res = subprocess.run(['pytest', 'tests/test_protocol_invariants.py::TestProtocolInvariants::test_monotonic_chain_index'], capture_output=True, text=True)
with open('err.txt', 'w', encoding='utf-8') as f:
    f.write(res.stdout)
    f.write(res.stderr)
