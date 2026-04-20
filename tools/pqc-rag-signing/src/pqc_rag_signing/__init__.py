"""PQC RAG Pipeline Signing - Quantum-safe chunk signing for RAG pipelines."""

from pqc_rag_signing.adapters import InMemoryAdapter, VectorStoreAdapter
from pqc_rag_signing.audit import RAGAuditEntry, RAGAuditLog
from pqc_rag_signing.chunk import ChunkMetadata, SignedChunk
from pqc_rag_signing.corpus import Corpus, CorpusManifest
from pqc_rag_signing.errors import (
    ChunkVerificationError,
    CorpusIntegrityError,
    KeyMismatchError,
    RAGSigningError,
    TamperedChunkError,
    UnsignedChunkError,
)
from pqc_rag_signing.signer import ChunkSigner, VerificationResult
from pqc_rag_signing.verifier import RetrievalResult, RetrievalVerifier

__version__ = "0.1.0"
__all__ = [
    "SignedChunk",
    "ChunkMetadata",
    "ChunkSigner",
    "VerificationResult",
    "Corpus",
    "CorpusManifest",
    "RetrievalVerifier",
    "RetrievalResult",
    "RAGAuditLog",
    "RAGAuditEntry",
    "VectorStoreAdapter",
    "InMemoryAdapter",
    "RAGSigningError",
    "ChunkVerificationError",
    "CorpusIntegrityError",
    "TamperedChunkError",
    "UnsignedChunkError",
    "KeyMismatchError",
]
