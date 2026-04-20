"""Abstract vector store adapter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from pqc_rag_signing.chunk import SignedChunk


class VectorStoreAdapter(ABC):
    """Base class for vector DB integrations.

    Implementations must preserve the full SignedChunk envelope (not just
    text + embedding) so verification is possible at retrieval time.
    Most vector DBs support arbitrary metadata - store ``chunk.to_dict()``
    as metadata alongside the embedding.
    """

    @abstractmethod
    def upsert(
        self,
        chunks: Iterable[SignedChunk],
        embeddings: list[list[float]],
    ) -> None:
        """Store signed chunks with their embeddings."""

    @abstractmethod
    def query(self, embedding: list[float], top_k: int = 5) -> list[SignedChunk]:
        """Retrieve top-k chunks for a query embedding.

        Returns SignedChunks with full envelope intact so verification works
        downstream.
        """

    @abstractmethod
    def count(self) -> int:
        """Return total number of chunks stored."""
