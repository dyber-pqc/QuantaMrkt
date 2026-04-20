"""Pytest fixtures for pqc-rag-signing tests."""

from __future__ import annotations

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_rag_signing import (
    ChunkMetadata,
    ChunkSigner,
    RAGAuditLog,
    SignedChunk,
)


@pytest.fixture
def ingest_identity() -> AgentIdentity:
    return AgentIdentity.create("test-ingest-pipeline")


@pytest.fixture
def attacker_identity() -> AgentIdentity:
    return AgentIdentity.create("evil-attacker")


@pytest.fixture
def signer(ingest_identity: AgentIdentity) -> ChunkSigner:
    return ChunkSigner(ingest_identity, corpus_id="test-corpus")


@pytest.fixture
def sample_metadata() -> ChunkMetadata:
    return ChunkMetadata(
        source="test-document.txt",
        chunk_index=0,
        total_chunks=3,
        start_offset=0,
        end_offset=42,
    )


@pytest.fixture
def sample_signed_chunk(
    signer: ChunkSigner,
    sample_metadata: ChunkMetadata,
) -> SignedChunk:
    return signer.sign_chunk(
        "The quick brown fox jumps over the lazy dog.",
        sample_metadata,
    )


@pytest.fixture
def sample_corpus_texts() -> dict[str, list[str]]:
    return {
        "handbook.txt": [
            "Employees must follow the PQC security policy.",
            "All data in transit uses ML-KEM key exchange.",
            "Model weights are signed with ML-DSA-87.",
        ],
        "policies.txt": [
            "Incident response requires quantum-safe attestation.",
            "Audit logs are append-only and hash-chained.",
        ],
    }


@pytest.fixture
def audit_log() -> RAGAuditLog:
    return RAGAuditLog()
