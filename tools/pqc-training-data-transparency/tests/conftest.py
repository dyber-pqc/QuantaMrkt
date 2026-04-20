"""Pytest fixtures."""

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_training_data import (
    CommitmentBuilder,
    CommitmentSigner,
    DataRecord,
)


@pytest.fixture
def signer_identity() -> AgentIdentity:
    return AgentIdentity.create("training-ingest")


@pytest.fixture
def signer(signer_identity: AgentIdentity) -> CommitmentSigner:
    return CommitmentSigner(signer_identity)


@pytest.fixture
def sample_records() -> list[DataRecord]:
    return [
        DataRecord(content=f"doc-{i}".encode(), metadata={"doc_id": i})
        for i in range(5)
    ]


@pytest.fixture
def odd_records() -> list[DataRecord]:
    return [
        DataRecord(content=f"odd-{i}".encode(), metadata={"doc_id": i})
        for i in range(7)   # odd count exercises promotion
    ]


@pytest.fixture
def single_record() -> DataRecord:
    return DataRecord(content=b"only-doc", metadata={"kind": "single"})


@pytest.fixture
def signed_commitment(signer, sample_records):
    builder = CommitmentBuilder("demo-dataset", "1.0.0")
    builder.add_records(sample_records)
    commitment = builder.build(description="fixture commitment")
    return signer.sign(commitment)
