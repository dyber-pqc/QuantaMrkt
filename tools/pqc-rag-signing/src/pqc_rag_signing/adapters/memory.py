"""In-memory vector store - reference implementation + useful for tests."""

from __future__ import annotations

import math
from typing import Iterable

from pqc_rag_signing.adapters.base import VectorStoreAdapter
from pqc_rag_signing.chunk import SignedChunk


def cosine_similarity(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(y * y for y in b)) or 1.0
    return dot / (na * nb)


class InMemoryAdapter(VectorStoreAdapter):
    """Simple in-memory vector store. Not for production - use it in tests
    and as a template for real DB adapters (Chroma, Pinecone, Qdrant, etc.)."""

    def __init__(self) -> None:
        self._records: list[tuple[SignedChunk, list[float]]] = []

    def upsert(
        self,
        chunks: Iterable[SignedChunk],
        embeddings: list[list[float]],
    ) -> None:
        chunk_list = list(chunks)
        if len(chunk_list) != len(embeddings):
            raise ValueError(
                f"chunk count {len(chunk_list)} != embedding count {len(embeddings)}"
            )
        for chunk, emb in zip(chunk_list, embeddings):
            self._records.append((chunk, list(emb)))

    def query(self, embedding: list[float], top_k: int = 5) -> list[SignedChunk]:
        scored = [
            (cosine_similarity(embedding, emb), chunk)
            for chunk, emb in self._records
        ]
        scored.sort(key=lambda t: t[0], reverse=True)
        return [c for _, c in scored[:top_k]]

    def count(self) -> int:
        return len(self._records)

    def clear(self) -> None:
        self._records.clear()
