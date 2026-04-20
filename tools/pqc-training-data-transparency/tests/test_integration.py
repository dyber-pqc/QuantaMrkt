"""Integration tests - end-to-end build/sign/prove/verify."""

from __future__ import annotations

from quantumshield.identity.agent import AgentIdentity

from pqc_training_data import (
    CommitmentBuilder,
    CommitmentSigner,
    CommitmentVerifier,
    DataRecord,
    TrainingCommitment,
)


def test_full_pipeline_build_sign_prove_verify() -> None:
    identity = AgentIdentity.create("big-creator")
    signer = CommitmentSigner(identity)

    records = [
        DataRecord(content=f"record-{i}".encode(), metadata={"id": i, "kind": "doc"})
        for i in range(100)
    ]
    builder = CommitmentBuilder("ds-100", "1.2.3")
    builder.add_records(records)
    commitment = signer.sign(builder.build(description="100 records"))

    # Pick a few arbitrary indices and verify each
    for idx in (0, 17, 42, 63, 99):
        proof = builder.tree.inclusion_proof(idx)
        result = CommitmentVerifier.verify(records[idx], proof, commitment)
        assert result.fully_verified, (
            f"verification failed for index {idx}: {result.error}"
        )


def test_missing_record_rejected() -> None:
    identity = AgentIdentity.create("honest")
    signer = CommitmentSigner(identity)

    records = [
        DataRecord(content=f"legit-{i}".encode(), metadata={"id": i})
        for i in range(20)
    ]
    builder = CommitmentBuilder("legit-ds", "1.0.0")
    builder.add_records(records)
    commitment = signer.sign(builder.build())

    # Attacker fabricates: tries to claim doc-999 is in the tree.
    # Their best attack: reuse a real slot's proof with a forged record.
    forged = DataRecord(content=b"doc-999-never-added", metadata={"id": 999})
    for attack_idx in (0, 5, 10, 19):
        proof = builder.tree.inclusion_proof(attack_idx)
        result = CommitmentVerifier.verify(forged, proof, commitment)
        assert result.fully_verified is False
        assert result.leaf_matches_record is False


def test_commitment_serialization_survives_network() -> None:
    identity = AgentIdentity.create("serializer")
    signer = CommitmentSigner(identity)
    records = [
        DataRecord(content=f"s-{i}".encode(), metadata={"id": i}) for i in range(6)
    ]
    builder = CommitmentBuilder("serial-ds", "1.0.0")
    builder.add_records(records)
    commitment = signer.sign(builder.build())

    # Round-trip commitment through JSON (simulating network / disk)
    blob = commitment.to_json()
    restored = TrainingCommitment.from_json(blob)

    # Signature still verifies
    assert CommitmentSigner.verify(restored) is True

    # Still accepts valid inclusion proofs for the same tree
    proof = builder.tree.inclusion_proof(3)
    result = CommitmentVerifier.verify(records[3], proof, restored)
    assert result.fully_verified is True
