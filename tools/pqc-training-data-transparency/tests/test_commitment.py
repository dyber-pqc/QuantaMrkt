"""Tests for CommitmentBuilder, TrainingCommitment, CommitmentSigner."""

from __future__ import annotations

import pytest
from quantumshield.core.keys import _BACKEND

from pqc_training_data import (
    CommitmentBuilder,
    CommitmentSigner,
    DataRecord,
    TrainingCommitment,
)


def test_builder_populates_commitment_fields(
    sample_records: list[DataRecord],
) -> None:
    builder = CommitmentBuilder("my-dataset", "2.0.1")
    builder.add_records(sample_records)
    builder.licenses = ["mit"]
    builder.tags = ["demo"]
    builder.extra = {"pipeline": "v3"}
    commitment = builder.build(description="test corpus")

    assert commitment.dataset_name == "my-dataset"
    assert commitment.dataset_version == "2.0.1"
    assert commitment.description == "test corpus"
    assert commitment.record_count == len(sample_records)
    assert commitment.root and len(commitment.root) == 64
    assert commitment.commitment_id.startswith("urn:pqc-td:")
    assert commitment.licenses == ["mit"]
    assert commitment.tags == ["demo"]
    assert commitment.extra == {"pipeline": "v3"}
    assert commitment.created_at  # non-empty iso string
    # Unsigned at this point
    assert commitment.signature == ""
    assert commitment.signer_did == ""


def test_commitment_to_json_from_json_roundtrip(signed_commitment: TrainingCommitment) -> None:
    blob = signed_commitment.to_json()
    restored = TrainingCommitment.from_json(blob)
    assert restored == signed_commitment
    # And canonical bytes are identical (this is what signatures cover)
    assert restored.canonical_bytes() == signed_commitment.canonical_bytes()


def test_sign_populates_signature_fields(
    signer: CommitmentSigner,
    sample_records: list[DataRecord],
) -> None:
    builder = CommitmentBuilder("ds", "1.0.0")
    builder.add_records(sample_records)
    commitment = builder.build()
    signed = signer.sign(commitment)
    assert signed.signature
    assert signed.signer_did.startswith("did:pqaid:")
    assert signed.algorithm
    assert signed.public_key
    assert signed.signed_at


def test_verify_valid_signature(signed_commitment: TrainingCommitment) -> None:
    assert CommitmentSigner.verify(signed_commitment) is True


def test_verify_tampered_dataset_name_fails_when_real_pqc_backend(
    signed_commitment: TrainingCommitment,
) -> None:
    # Ed25519 fallback does real verification, so this test runs there too.
    # Only skip for the pure-stub backend (no real signatures at all).
    if _BACKEND == "stub":
        pytest.skip("requires real PQC or Ed25519 backend")
    tampered = TrainingCommitment.from_json(signed_commitment.to_json())
    tampered.dataset_name = "evil-renamed-dataset"
    assert CommitmentSigner.verify(tampered) is False


def test_canonical_bytes_deterministic(
    signer: CommitmentSigner,
    sample_records: list[DataRecord],
) -> None:
    builder = CommitmentBuilder("ds", "1.0.0")
    builder.add_records(sample_records)
    commitment = builder.build(description="x")
    cb1 = commitment.canonical_bytes()
    cb2 = commitment.canonical_bytes()
    assert cb1 == cb2
    # Permuting tags/licenses doesn't change canonical output
    commitment.tags = ["b", "a"]
    cb3 = commitment.canonical_bytes()
    commitment.tags = ["a", "b"]
    cb4 = commitment.canonical_bytes()
    assert cb3 == cb4
