"""Tests for InMemoryAdapter."""

from __future__ import annotations

import hashlib

import pytest

from pqc_rag_signing import ChunkSigner, InMemoryAdapter
from pqc_rag_signing.adapters.memory import cosine_similarity


def _embed(text: str, dim: int = 16) -> list[float]:
    h = hashlib.sha256(text.encode()).digest()
    return [(b - 128) / 128.0 for b in h[:dim]]


def test_upsert_and_count(signer: ChunkSigner) -> None:
    chunks = signer.sign_chunks(["a", "b", "c"], source="s.txt")
    store = InMemoryAdapter()
    store.upsert(chunks, [_embed(c.text) for c in chunks])
    assert store.count() == 3


def test_query_returns_top_k(signer: ChunkSigner) -> None:
    texts = ["quantum computers", "apples are red", "post-quantum crypto"]
    chunks = signer.sign_chunks(texts, source="s.txt")
    store = InMemoryAdapter()
    store.upsert(chunks, [_embed(c.text) for c in chunks])
    results = store.query(_embed("quantum"), top_k=2)
    assert len(results) == 2
    # Confirm result objects are SignedChunks with full envelope
    for r in results:
        assert r.signature
        assert r.public_key
        assert r.content_hash


def test_query_preserves_chunk_envelope(signer: ChunkSigner) -> None:
    chunks = signer.sign_chunks(["hello"], source="s.txt")
    store = InMemoryAdapter()
    store.upsert(chunks, [_embed(c.text) for c in chunks])
    [retrieved] = store.query(_embed("hello"), top_k=1)
    # Verification must still succeed after round-tripping through the store.
    result = ChunkSigner.verify_chunk(retrieved)
    assert result.valid


def test_mismatched_embeddings_raises(signer: ChunkSigner) -> None:
    chunks = signer.sign_chunks(["a", "b"], source="s.txt")
    store = InMemoryAdapter()
    with pytest.raises(ValueError):
        store.upsert(chunks, [_embed("a")])


def test_cosine_similarity_edge_cases() -> None:
    assert cosine_similarity([], []) == 0.0
    assert cosine_similarity([1.0, 0.0], [1.0, 0.0, 0.0]) == 0.0
    # Identical vectors -> 1.0
    v = [1.0, 2.0, 3.0]
    assert cosine_similarity(v, v) == pytest.approx(1.0)
