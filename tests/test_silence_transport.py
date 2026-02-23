from __future__ import annotations

import numpy as np
import pytest

# transports/ is excluded from the public repository
pytest.importorskip("idre_clean.transports.idre_silence")
from idre_clean.transports.idre_silence import IDRESilenceProtocol

def test_silence_bytes_roundtrip() -> None:
    # Keep the payload small and the profile fast so CI runs quickly.
    proto = IDRESilenceProtocol(symbol_cycles=1, preamble_cycles=6, fec_repeat=3)
    payload = b"IDRE-SILENCE:" + (b"abc123" * 10)
    audio = proto.encode_bytes(payload)
    out = proto.decode_bytes(audio)
    assert out == payload

def test_silence_decode_rejects_garbage() -> None:
    proto = IDRESilenceProtocol(fec_repeat=3)
    garbage = np.zeros(4096, dtype=np.float32)
    out = proto.decode_bytes(garbage)
    assert out is None
