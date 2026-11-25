"""Tests for Task 1: IDRE v3 Profile, Wire Capacity, Anti-Downgrade, and CLI version gate."""

from __future__ import annotations

import json
import secrets
from pathlib import Path

import pytest

from core.profile_v3 import (
    AEAD_TAG_BYTES,
    CODEC_FRAMING_OVERHEAD_BYTES,
    DIR_I2R,
    DIR_R2I,
    ENCRYPTED_HEADER_OVERHEAD_BYTES,
    MAX_WIRE_CELL_BYTES,
    MSG_TYPE_DATA,
    PROTOCOL_VERSION_V3,
    ROLE_INITIATOR,
    WIRE_HEADER_BYTES,
    MessageContextV3,
    ProfileV3,
    ProfileValidationError,
    ProvisioningBundleV3,
    TranscriptV3,
    canonical_profile,
    compute_vocab_digest_v3,
    max_usable_payload_bytes,
    public_profile_metadata,
    validate_profile,
)
from core.vocab_codec import load_vocab
from hive.cli import configure_node_from_args, get_node_argparser


@pytest.fixture
def sample_vocab(tmp_path: Path):
    p = tmp_path / "vocab.json"
    p.write_text(json.dumps(["red", "blue", "green", " "]), encoding="utf-8")
    return load_vocab(str(p))


def _valid_profile(vocab, **overrides) -> ProfileV3:
    base = dict(
        bundle_id=b"\x11" * 16,
        expected_vocab_digest=compute_vocab_digest_v3(vocab),
    )
    base.update(overrides)
    return ProfileV3(**base)


def test_valid_profile_and_canonical_encoding(sample_vocab):
    p1 = _valid_profile(sample_vocab, immutable_anchor_ids=(20, 10))
    p2 = _valid_profile(sample_vocab, immutable_anchor_ids=(10, 20))
    validate_profile(p1, sample_vocab)
    assert canonical_profile(p1) == canonical_profile(p2)

    pub = public_profile_metadata(p1)
    assert "expected_vocab_digest" not in pub
    assert pub["bundle_id"] == p1.bundle_id.hex()


def test_usable_cell_capacity_math(sample_vocab):
    assert MAX_WIRE_CELL_BYTES == 4096
    std_cap = max_usable_payload_bytes(encrypted_headers=False)
    enc_cap = max_usable_payload_bytes(encrypted_headers=True)
    assert std_cap == 4096 - WIRE_HEADER_BYTES - AEAD_TAG_BYTES - CODEC_FRAMING_OVERHEAD_BYTES
    assert std_cap == 4023
    assert enc_cap == std_cap - ENCRYPTED_HEADER_OVERHEAD_BYTES
    assert enc_cap == 3943

    # Exact capacity accepted
    validate_profile(_valid_profile(sample_vocab, max_plaintext_bytes=std_cap), sample_vocab)
    validate_profile(
        _valid_profile(sample_vocab, encrypted_headers=True, max_plaintext_bytes=enc_cap),
        sample_vocab,
    )

    # Legacy 65535 or even +1 over capacity rejected
    with pytest.raises(ProfileValidationError):
        validate_profile(_valid_profile(sample_vocab, max_plaintext_bytes=65535), sample_vocab)
    with pytest.raises(ProfileValidationError):
        validate_profile(_valid_profile(sample_vocab, max_plaintext_bytes=std_cap + 1), sample_vocab)
    with pytest.raises(ProfileValidationError):
        validate_profile(
            _valid_profile(sample_vocab, encrypted_headers=True, max_plaintext_bytes=enc_cap + 1),
            sample_vocab,
        )


@pytest.mark.parametrize(
    "bad_kwargs",
    [
        {"plasticity": False},
        {"freeze_field": True},
        {"field_backend": "frozen"},
        {"content_codec": "utf8"},
        {"vocab_allow_literals": True},
        {"allow_v2_fallback": True},
        {"allow_seed_only_offline_open": True},
        {"healing_mode": "multiverse"},
        {"protocol_version": "IDRE/2.0"},
        {"suite": "LEGACY-XOR"},
        {"state_scope": "network_global"},
        {"max_in_flight": 2},
        {"max_wire_cell_bytes": 4097},
        {"embedding_dim": 0},
    ],
)
def test_invalid_profile_configurations_fail_closed(sample_vocab, bad_kwargs):
    p = _valid_profile(sample_vocab, **bad_kwargs)
    with pytest.raises(ProfileValidationError):
        validate_profile(p, sample_vocab)
    with pytest.raises(ProfileValidationError):
        canonical_profile(p)


def test_wrong_vocab_binding_and_non_opaque_bundle_id_rejected(sample_vocab, tmp_path: Path):
    # Reordered tokens must fail digest check
    reordered_path = tmp_path / "reordered.json"
    reordered_path.write_text(json.dumps(["blue", "red", "green", " "]), encoding="utf-8")
    reordered_vocab = load_vocab(str(reordered_path))

    p = _valid_profile(sample_vocab)
    with pytest.raises(ProfileValidationError):
        validate_profile(p, reordered_vocab)

    # Reusing private vocab digest prefix as public bundle_id must fail
    leaked_bundle = _valid_profile(
        sample_vocab,
        bundle_id=compute_vocab_digest_v3(sample_vocab)[:16],
    )
    with pytest.raises(ProfileValidationError):
        validate_profile(leaked_bundle, sample_vocab)


def test_provisioning_bundle_transcript_and_context(sample_vocab):
    profile = _valid_profile(sample_vocab)
    bundle = ProvisioningBundleV3(
        profile=profile,
        network_secret=secrets.token_bytes(32),
        field_init_secret=secrets.token_bytes(32),
        expected_vocab_digest=profile.expected_vocab_digest,
        local_node_id="node-a",
        bundle_epoch=1,
    )
    bundle.validate(sample_vocab)

    # Short secret rejected
    weak = ProvisioningBundleV3(
        profile=profile,
        network_secret=b"short-seed",
        field_init_secret=secrets.token_bytes(32),
        expected_vocab_digest=profile.expected_vocab_digest,
        local_node_id="node-a",
    )
    with pytest.raises(ProfileValidationError):
        weak.validate(sample_vocab)

    # Transcript & context canonical bytes are deterministic and direction-separated
    tr = TranscriptV3(
        profile_bytes=canonical_profile(profile),
        session_id=b"\x22" * 16,
        initiator_id="node-a",
        responder_id="node-b",
        initiator_nonce=b"\x33" * 32,
        responder_nonce=b"\x44" * 32,
    )
    assert tr.canonical_bytes().startswith(b"IDRE-V3-TRANSCRIPT\x00")

    ctx_i2r = MessageContextV3(
        protocol_version=PROTOCOL_VERSION_V3,
        bundle_id=profile.bundle_id,
        session_id=b"\x22" * 16,
        role=ROLE_INITIATOR,
        peer_id="node-b",
        direction=DIR_I2R,
        epoch=1,
        seq=0,
        msg_type=MSG_TYPE_DATA,
    )
    ctx_r2i = MessageContextV3(
        protocol_version=PROTOCOL_VERSION_V3,
        bundle_id=profile.bundle_id,
        session_id=b"\x22" * 16,
        role=ROLE_INITIATOR,
        peer_id="node-b",
        direction=DIR_R2I,
        epoch=1,
        seq=0,
        msg_type=MSG_TYPE_DATA,
    )
    assert ctx_i2r.canonical_bytes() != ctx_r2i.canonical_bytes()


def test_cli_v3_version_selection_rejects_downgrade_and_bad_flags(tmp_path: Path):
    ap = get_node_argparser()
    # Default remains v2
    default_args = ap.parse_args(["--node-id", "A", "--pepper", "p"])
    assert default_args.protocol_version == "v2"

    # v3 with disabled plasticity fails closed
    bad_v3 = ap.parse_args(
        [
            "--protocol-version",
            "v3",
            "--node-id",
            "A",
            "--pepper",
            "p",
            "--content-codec",
            "vocab",
            "--no-vocab-allow-literals",
            "--max-plaintext-bytes",
            "4023",
        ]
    )
    with pytest.raises(ProfileValidationError, match="plasticity"):
        configure_node_from_args(bad_v3)

    # v3 missing required provisioning secrets fails closed and never falls back to v2
    incomplete_v3 = ap.parse_args(
        [
            "--protocol-version",
            "v3",
            "--node-id",
            "A",
            "--pepper",
            "p",
            "--backend",
            "lattice",
            "--enable-plasticity",
            "--content-codec",
            "vocab",
            "--no-vocab-allow-literals",
            "--max-plaintext-bytes",
            "4023",
        ]
    )
    with pytest.raises(ProfileValidationError, match="refusing to fall back to v2"):
        configure_node_from_args(incomplete_v3)
