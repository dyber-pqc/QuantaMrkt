"""Tests for SignedChunk and ChunkMetadata."""

from __future__ import annotations

from pqc_rag_signing import ChunkMetadata, SignedChunk


def test_content_hash_deterministic(sample_metadata: ChunkMetadata) -> None:
    text = "deterministic content"
    nonce = "deadbeef"
    h1 = SignedChunk.compute_content_hash(text, sample_metadata, nonce)
    h2 = SignedChunk.compute_content_hash(text, sample_metadata, nonce)
    assert h1 == h2
    assert len(h1) == 64  # SHA3-256 hex digest


def test_content_hash_changes_with_text(sample_metadata: ChunkMetadata) -> None:
    nonce = "deadbeef"
    h1 = SignedChunk.compute_content_hash("alpha", sample_metadata, nonce)
    h2 = SignedChunk.compute_content_hash("beta", sample_metadata, nonce)
    assert h1 != h2


def test_content_hash_changes_with_metadata() -> None:
    text = "same text"
    nonce = "deadbeef"
    meta_a = ChunkMetadata(source="a.txt", chunk_index=0, total_chunks=1)
    meta_b = ChunkMetadata(source="b.txt", chunk_index=0, total_chunks=1)
    h1 = SignedChunk.compute_content_hash(text, meta_a, nonce)
    h2 = SignedChunk.compute_content_hash(text, meta_b, nonce)
    assert h1 != h2


def test_content_hash_changes_with_nonce(sample_metadata: ChunkMetadata) -> None:
    text = "same text"
    h1 = SignedChunk.compute_content_hash(text, sample_metadata, "nonce-a")
    h2 = SignedChunk.compute_content_hash(text, sample_metadata, "nonce-b")
    assert h1 != h2


def test_to_dict_roundtrip(sample_signed_chunk: SignedChunk) -> None:
    as_dict = sample_signed_chunk.to_dict()
    restored = SignedChunk.from_dict(as_dict)
    assert restored.chunk_id == sample_signed_chunk.chunk_id
    assert restored.text == sample_signed_chunk.text
    assert restored.content_hash == sample_signed_chunk.content_hash
    assert restored.signature == sample_signed_chunk.signature
    assert restored.public_key == sample_signed_chunk.public_key
    assert restored.signer_did == sample_signed_chunk.signer_did
    assert restored.algorithm == sample_signed_chunk.algorithm
    assert restored.nonce == sample_signed_chunk.nonce
    assert restored.corpus_id == sample_signed_chunk.corpus_id
    assert restored.metadata.source == sample_signed_chunk.metadata.source
    assert restored.metadata.chunk_index == sample_signed_chunk.metadata.chunk_index


def test_metadata_extra_field() -> None:
    meta = ChunkMetadata(
        source="x.pdf",
        chunk_index=0,
        total_chunks=1,
        extra={"author": "Alice", "year": 2026},
    )
    d = meta.to_dict()
    assert d["extra"]["author"] == "Alice"
    assert d["extra"]["year"] == 2026
