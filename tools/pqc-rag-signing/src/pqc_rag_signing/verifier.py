"""Retrieval-time verification wrapper for RAG pipelines."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

from pqc_rag_signing.chunk import SignedChunk
from pqc_rag_signing.errors import TamperedChunkError
from pqc_rag_signing.signer import ChunkSigner, VerificationResult


@dataclass
class RetrievalResult:
    """Aggregate result of verifying a batch of retrieved chunks."""

    total: int
    verified: list[SignedChunk] = field(default_factory=list)
    failed: list[tuple[SignedChunk, VerificationResult]] = field(default_factory=list)
    verified_at: str = ""
    trusted_signers: set[str] = field(default_factory=set)

    @property
    def all_verified(self) -> bool:
        return len(self.failed) == 0

    @property
    def verified_count(self) -> int:
        return len(self.verified)

    @property
    def failed_count(self) -> int:
        return len(self.failed)

    def verified_texts(self) -> list[str]:
        """Return ONLY the text content of verified chunks - safe for LLM."""
        return [c.text for c in self.verified]


class RetrievalVerifier:
    """Verify chunks retrieved from a vector DB before passing to an LLM.

    Supports optional allow-list of trusted signer DIDs. Chunks signed by
    anyone NOT in the allow-list (if set) are rejected even if cryptographically
    valid.

    Usage:
        verifier = RetrievalVerifier(
            trusted_signers={"did:pqaid:abc123..."},
            strict=True,
        )
        result = verifier.verify_retrieved(signed_chunks)
        if not result.all_verified:
            # handle failures
            ...
        safe_texts = result.verified_texts()
    """

    def __init__(
        self,
        trusted_signers: set[str] | None = None,
        strict: bool = True,
    ) -> None:
        self.trusted_signers = trusted_signers
        self.strict = strict

    def verify_retrieved(
        self,
        chunks: Iterable[SignedChunk],
    ) -> RetrievalResult:
        """Verify each chunk, bucket into verified vs failed."""
        result = RetrievalResult(
            total=0,
            verified_at=datetime.now(timezone.utc).isoformat(),
            trusted_signers=self.trusted_signers or set(),
        )
        for chunk in chunks:
            result.total += 1
            verification = ChunkSigner.verify_chunk(chunk)

            if (
                verification.valid
                and self.trusted_signers
                and chunk.signer_did not in self.trusted_signers
            ):
                verification = VerificationResult(
                    valid=False,
                    chunk_id=chunk.chunk_id,
                    signer_did=chunk.signer_did,
                    algorithm=chunk.algorithm,
                    error=f"signer {chunk.signer_did} not in trusted allow-list",
                )

            if verification.valid:
                result.verified.append(chunk)
            else:
                result.failed.append((chunk, verification))

        return result

    def verify_or_raise(
        self,
        chunks: Iterable[SignedChunk],
    ) -> list[SignedChunk]:
        """Like verify_retrieved, but raises on any failure."""
        result = self.verify_retrieved(chunks)
        if not result.all_verified:
            first_fail = result.failed[0]
            raise TamperedChunkError(
                f"{result.failed_count}/{result.total} chunks failed "
                f"verification. First failure: {first_fail[1].error}"
            )
        return result.verified
