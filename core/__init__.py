"""IDRE clean core (field-bound primitives).

This is a minimal extraction intended to become the standalone IDRE repo.
"""

from .field import derive_locked_plane, scan_fingerprint_bits, seeded_unit_vector
from .primitives import compute_block_salt, derive_keystream_and_permutation
from .session import HiveSession, NonceWindow
from .wire import MAC_LEN, canonical_json, frame_payload, unframe_payload
from .wire_bin import pack_receive_envelope, pack_wire_message, unpack_receive_envelope, unpack_wire_message
from .vocab_codec import Vocab, decode_text, encode_text, load_vocab, load_vocab_registry, peek_vocab_id
from .vocab_store import read_vocab_bin, write_vocab_bin

__all__ = [
    "MAC_LEN",
    "HiveSession",
    "NonceWindow",
    "Vocab",
    "canonical_json",
    "compute_block_salt",
    "decode_text",
    "derive_keystream_and_permutation",
    "derive_locked_plane",
    "encode_text",
    "frame_payload",
    "load_vocab",
    "load_vocab_registry",
    "pack_receive_envelope",
    "pack_wire_message",
    "peek_vocab_id",
    "scan_fingerprint_bits",
    "seeded_unit_vector",
    "unpack_receive_envelope",
    "unpack_wire_message",
    "unframe_payload",
    "read_vocab_bin",
    "write_vocab_bin",
]
