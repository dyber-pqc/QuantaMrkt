"""Exception hierarchy for pqc-rag-signing."""

from __future__ import annotations


class RAGSigningError(Exception):
    """Base exception for all pqc-rag-signing errors."""


class ChunkVerificationError(RAGSigningError):
    """Raised when a signed chunk fails cryptographic verification."""


class TamperedChunkError(ChunkVerificationError):
    """Raised when chunk content hash doesn't match the signed hash."""


class UnsignedChunkError(RAGSigningError):
    """Raised when an unsigned chunk is encountered in a verified pipeline."""


class CorpusIntegrityError(RAGSigningError):
    """Raised when the corpus manifest root doesn't match stored chunks."""


class KeyMismatchError(ChunkVerificationError):
    """Raised when the chunk signer DID doesn't match the expected signer."""
