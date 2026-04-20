"""Tests for the CommitmentVerifier end-to-end flow."""

from __future__ import annotations

import pytest

from pqc_training_data import (
    CommitmentBuilder,
    CommitmentSigner,
    CommitmentVerifier,
    DataRecord,
    TrainingCommitment,
)
from pqc_training_data.errors import CommitmentVerificationError


def _build_signed(
    signer: CommitmentSigner, records: list[DataRecord]
) -> tuple[CommitmentBuilder, TrainingCommitment]:
    builder = CommitmentBuilder("verifier-ds", "1.0.0")
    builder.add_records(records)
    commitment = signer.sign(builder.build())
    return builder, commitment


def test_verify_success_for_valid_record(
    signer: CommitmentSigner,
    sample_records: list[DataRecord],
) -> None:
    builder, commitment = _build_signed(signer, sample_records)
    proof = builder.tree.inclusion_proof(2)
    result = CommitmentVerifier.verify(sample_records[2], proof, commitment)
    assert result.fully_verified is True
    assert result.error is None


def test_verify_fails_when_record_not_in_tree(
    signer: CommitmentSigner,
    sample_records: list[DataRecord],
) -> None:
    builder, commitment = _build_signed(signer, sample_records)
    proof = builder.tree.inclusion_proof(2)
    bogus_record = DataRecord(content=b"never-was-added", metadata={"doc_id": 999})
    result = CommitmentVerifier.verify(bogus_record, proof, commitment)
    assert result.fully_verified is False
    assert result.leaf_matches_record is False


def test_verify_fails_when_proof_tampered(
    signer: CommitmentSigner,
    sample_records: list[DataRecord],
) -> None:
    builder, commitment = _build_signed(signer, sample_records)
    proof = builder.tree.inclusion_proof(2)
    # Tamper with a sibling hash
    tampered_siblings = list(proof.siblings)
    first = tampered_siblings[0]
    tampered_siblings[0] = ("f" if first[0] != "f" else "0") + first[1:]
    tampered_proof = type(proof)(
        leaf_hash=proof.leaf_hash,
        index=proof.index,
        tree_size=proof.tree_size,
        root=proof.root,
        siblings=tampered_siblings,
        directions=list(proof.directions),
    )
    result = CommitmentVerifier.verify(sample_records[2], tampered_proof, commitment)
    assert result.fully_verified is False
    assert result.proof_valid is False


def test_verify_fails_when_commitment_unsigned(
    sample_records: list[DataRecord],
) -> None:
    builder = CommitmentBuilder("unsigned-ds", "1.0.0")
    builder.add_records(sample_records)
    commitment = builder.build()  # no .sign() call
    proof = builder.tree.inclusion_proof(0)
    result = CommitmentVerifier.verify(sample_records[0], proof, commitment)
    assert result.signature_valid is False
    assert result.fully_verified is False


def test_verify_or_raise_raises_on_mismatch(
    signer: CommitmentSigner,
    sample_records: list[DataRecord],
) -> None:
    builder, commitment = _build_signed(signer, sample_records)
    proof = builder.tree.inclusion_proof(0)
    wrong_record = DataRecord(content=b"nope", metadata={})
    with pytest.raises(CommitmentVerificationError):
        CommitmentVerifier.verify_or_raise(wrong_record, proof, commitment)


def test_verify_or_raise_silent_on_success(
    signer: CommitmentSigner,
    sample_records: list[DataRecord],
) -> None:
    builder, commitment = _build_signed(signer, sample_records)
    proof = builder.tree.inclusion_proof(4)
    # Should not raise
    CommitmentVerifier.verify_or_raise(sample_records[4], proof, commitment)
