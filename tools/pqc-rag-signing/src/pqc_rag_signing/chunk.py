"""Signed chunk data structures."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class ChunkMetadata:
    """Metadata about a chunk's source (document, position, etc.)."""

    source: str
    chunk_index: int
    total_chunks: int
    start_offset: int = 0
    end_offset: int = 0
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SignedChunk:
    """A chunk of text with a PQC signature envelope.

    This is the unit stored in a vector DB. The ``text`` is the content used
    for embedding; the ``_pqc`` envelope is verified at retrieval time.
    """

    chunk_id: str
    text: str
    metadata: ChunkMetadata
    content_hash: str
    signer_did: str
    algorithm: str
    signature: str
    public_key: str
    signed_at: str
    corpus_id: str | None = None
    nonce: str = ""

    @staticmethod
    def compute_content_hash(text: str, metadata: ChunkMetadata, nonce: str) -> str:
        """Canonical SHA3-256 of chunk content + metadata + nonce.

        Deterministic: same (text, metadata, nonce) produces the same hash, always.
        """
        canonical = json.dumps(
            {
                "text": text,
                "metadata": metadata.to_dict(),
                "nonce": nonce,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha3_256(canonical).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Serialize for storage in a vector DB (the whole envelope)."""
        return {
            "chunk_id": self.chunk_id,
            "text": self.text,
            "metadata": self.metadata.to_dict(),
            "content_hash": self.content_hash,
            "signer_did": self.signer_did,
            "algorithm": self.algorithm,
            "signature": self.signature,
            "public_key": self.public_key,
            "signed_at": self.signed_at,
            "corpus_id": self.corpus_id,
            "nonce": self.nonce,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SignedChunk:
        """Deserialize from stored dict."""
        meta = data["metadata"]
        if isinstance(meta, dict):
            meta = ChunkMetadata(
                source=meta["source"],
                chunk_index=meta["chunk_index"],
                total_chunks=meta["total_chunks"],
                start_offset=meta.get("start_offset", 0),
                end_offset=meta.get("end_offset", 0),
                extra=meta.get("extra", {}),
            )
        return cls(
            chunk_id=data["chunk_id"],
            text=data["text"],
            metadata=meta,
            content_hash=data["content_hash"],
            signer_did=data["signer_did"],
            algorithm=data["algorithm"],
            signature=data["signature"],
            public_key=data["public_key"],
            signed_at=data["signed_at"],
            corpus_id=data.get("corpus_id"),
            nonce=data.get("nonce", ""),
        )
