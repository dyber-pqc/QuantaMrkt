"""Chunk signing and verification using ML-DSA."""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.signatures import sign, verify
from quantumshield.identity.agent import AgentIdentity

from pqc_rag_signing.chunk import ChunkMetadata, SignedChunk
from pqc_rag_signing.errors import ChunkVerificationError


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of verifying a SignedChunk."""

    valid: bool
    chunk_id: str
    signer_did: str | None
    algorithm: str | None
    error: str | None = None

    def raise_if_invalid(self) -> None:
        """Raise ChunkVerificationError if this result is invalid."""
        if not self.valid:
            raise ChunkVerificationError(
                f"Chunk {self.chunk_id} failed verification: {self.error}"
            )


class ChunkSigner:
    """Signs RAG chunks with a fixed AgentIdentity.

    Usage:
        identity = AgentIdentity.create("my-ingest-pipeline")
        signer = ChunkSigner(identity)
        signed = signer.sign_chunk("text content", metadata)
        # store signed.to_dict() in vector DB
    """

    def __init__(self, identity: AgentIdentity, corpus_id: str | None = None) -> None:
        self.identity = identity
        self.corpus_id = corpus_id

    # -- signing ------------------------------------------------------------

    def sign_chunk(
        self,
        text: str,
        metadata: ChunkMetadata,
        chunk_id: str | None = None,
    ) -> SignedChunk:
        """Sign a single chunk. Returns the full signed envelope."""
        chunk_id = chunk_id or f"chunk-{uuid.uuid4().hex[:16]}"
        nonce = os.urandom(8).hex()
        content_hash = SignedChunk.compute_content_hash(text, metadata, nonce)
        sig = sign(bytes.fromhex(content_hash), self.identity.signing_keypair)
        return SignedChunk(
            chunk_id=chunk_id,
            text=text,
            metadata=metadata,
            content_hash=content_hash,
            signer_did=self.identity.did,
            algorithm=self.identity.signing_keypair.algorithm.value,
            signature=sig.hex(),
            public_key=self.identity.signing_keypair.public_key.hex(),
            signed_at=datetime.now(timezone.utc).isoformat(),
            corpus_id=self.corpus_id,
            nonce=nonce,
        )

    def sign_chunks(
        self,
        texts: Iterable[str],
        source: str,
    ) -> list[SignedChunk]:
        """Sign a batch of chunks from a single source document.

        Metadata (chunk_index, total_chunks, offsets) is auto-computed.
        """
        text_list = list(texts)
        total = len(text_list)
        offset = 0
        signed: list[SignedChunk] = []
        for i, text in enumerate(text_list):
            meta = ChunkMetadata(
                source=source,
                chunk_index=i,
                total_chunks=total,
                start_offset=offset,
                end_offset=offset + len(text),
            )
            offset += len(text)
            signed.append(self.sign_chunk(text, meta))
        return signed

    # -- verification -------------------------------------------------------

    @staticmethod
    def verify_chunk(chunk: SignedChunk) -> VerificationResult:
        """Verify a SignedChunk's content hash and ML-DSA signature."""
        expected_hash = SignedChunk.compute_content_hash(
            chunk.text, chunk.metadata, chunk.nonce
        )
        if expected_hash != chunk.content_hash:
            return VerificationResult(
                valid=False,
                chunk_id=chunk.chunk_id,
                signer_did=chunk.signer_did,
                algorithm=chunk.algorithm,
                error=(
                    f"content hash mismatch (expected {expected_hash[:16]}, "
                    f"got {chunk.content_hash[:16]})"
                ),
            )

        try:
            algorithm = SignatureAlgorithm(chunk.algorithm)
        except ValueError:
            return VerificationResult(
                valid=False,
                chunk_id=chunk.chunk_id,
                signer_did=chunk.signer_did,
                algorithm=chunk.algorithm,
                error=f"unknown algorithm {chunk.algorithm}",
            )

        try:
            sig_valid = verify(
                bytes.fromhex(chunk.content_hash),
                bytes.fromhex(chunk.signature),
                bytes.fromhex(chunk.public_key),
                algorithm,
            )
        except Exception as exc:
            return VerificationResult(
                valid=False,
                chunk_id=chunk.chunk_id,
                signer_did=chunk.signer_did,
                algorithm=chunk.algorithm,
                error=f"signature verify failed: {exc}",
            )

        if not sig_valid:
            return VerificationResult(
                valid=False,
                chunk_id=chunk.chunk_id,
                signer_did=chunk.signer_did,
                algorithm=chunk.algorithm,
                error="invalid ML-DSA signature",
            )

        return VerificationResult(
            valid=True,
            chunk_id=chunk.chunk_id,
            signer_did=chunk.signer_did,
            algorithm=chunk.algorithm,
        )

    @staticmethod
    def verify_chunks(chunks: Iterable[SignedChunk]) -> list[VerificationResult]:
        return [ChunkSigner.verify_chunk(c) for c in chunks]
