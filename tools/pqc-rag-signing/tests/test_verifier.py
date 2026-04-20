"""Tests for RetrievalVerifier."""

from __future__ import annotations

from dataclasses import replace

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_rag_signing import (
    ChunkMetadata,
    ChunkSigner,
    RetrievalVerifier,
    TamperedChunkError,
)


def _signed_batch(identity: AgentIdentity, texts: list[str]) -> list:
    signer = ChunkSigner(identity)
    return signer.sign_chunks(texts, source="batch.txt")


def test_verify_retrieved_all_valid(ingest_identity: AgentIdentity) -> None:
    chunks = _signed_batch(ingest_identity, ["alpha", "beta", "gamma"])
    verifier = RetrievalVerifier()
    result = verifier.verify_retrieved(chunks)
    assert result.total == 3
    assert result.verified_count == 3
    assert result.failed_count == 0
    assert result.all_verified
    assert result.verified_texts() == ["alpha", "beta", "gamma"]


def test_verify_retrieved_detects_tampered_chunk(
    ingest_identity: AgentIdentity,
) -> None:
    chunks = _signed_batch(ingest_identity, ["alpha", "beta"])
    # Tamper with the text of the first chunk (hash will mismatch)
    tampered = replace(chunks[0], text="EVIL")
    bad_batch = [tampered, chunks[1]]
    verifier = RetrievalVerifier()
    result = verifier.verify_retrieved(bad_batch)
    assert not result.all_verified
    assert result.failed_count == 1
    assert result.verified_count == 1
    assert result.failed[0][0].chunk_id == tampered.chunk_id


def test_verify_retrieved_detects_untrusted_signer(
    ingest_identity: AgentIdentity,
    attacker_identity: AgentIdentity,
) -> None:
    good = _signed_batch(ingest_identity, ["safe content"])
    evil = _signed_batch(attacker_identity, ["poisoned content"])
    verifier = RetrievalVerifier(trusted_signers={ingest_identity.did})
    result = verifier.verify_retrieved(good + evil)
    assert result.verified_count == 1
    assert result.failed_count == 1
    assert result.failed[0][0].signer_did == attacker_identity.did
    assert "allow-list" in (result.failed[0][1].error or "")


def test_verify_or_raise_success(ingest_identity: AgentIdentity) -> None:
    chunks = _signed_batch(ingest_identity, ["alpha", "beta"])
    verifier = RetrievalVerifier()
    safe = verifier.verify_or_raise(chunks)
    assert len(safe) == 2


def test_verify_or_raise_raises_on_tamper(
    ingest_identity: AgentIdentity,
) -> None:
    chunks = _signed_batch(ingest_identity, ["alpha"])
    chunks[0] = replace(chunks[0], text="TAMPERED")
    verifier = RetrievalVerifier()
    with pytest.raises(TamperedChunkError):
        verifier.verify_or_raise(chunks)


def test_verified_texts_returns_only_safe_content(
    ingest_identity: AgentIdentity,
    attacker_identity: AgentIdentity,
) -> None:
    signer_good = ChunkSigner(ingest_identity)
    good = signer_good.sign_chunk(
        "TRUSTED",
        ChunkMetadata(source="a.txt", chunk_index=0, total_chunks=1),
    )
    signer_evil = ChunkSigner(attacker_identity)
    evil = signer_evil.sign_chunk(
        "POISON",
        ChunkMetadata(source="a.txt", chunk_index=1, total_chunks=2),
    )
    verifier = RetrievalVerifier(trusted_signers={ingest_identity.did})
    result = verifier.verify_retrieved([good, evil])
    texts = result.verified_texts()
    assert "TRUSTED" in texts
    assert "POISON" not in texts
