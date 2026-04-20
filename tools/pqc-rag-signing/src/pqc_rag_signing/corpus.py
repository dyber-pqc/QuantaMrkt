"""Corpus manifest - proves an entire set of chunks is intact."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterable

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.signatures import sign, verify
from quantumshield.identity.agent import AgentIdentity

from pqc_rag_signing.chunk import SignedChunk
from pqc_rag_signing.errors import CorpusIntegrityError
from pqc_rag_signing.signer import ChunkSigner


@dataclass
class CorpusManifest:
    """Merkle-ish manifest committing to an entire set of signed chunks.

    The manifest contains the sorted list of (chunk_id, content_hash) pairs,
    hashed into a single root. Any change to any chunk (add/remove/modify)
    changes the root, so the manifest is a compact proof of corpus integrity.
    """

    corpus_id: str
    name: str
    created_at: str
    chunk_count: int
    chunk_hashes: list[tuple[str, str]]
    root: str
    signer_did: str
    algorithm: str
    signature: str
    public_key: str

    @staticmethod
    def compute_root(chunk_hashes: list[tuple[str, str]]) -> str:
        """Compute the deterministic manifest root over chunk hashes.

        We sort by chunk_id for determinism, concatenate, and SHA3-256.
        """
        sorted_pairs = sorted(chunk_hashes, key=lambda p: p[0])
        concat = "|".join(f"{cid}:{ch}" for cid, ch in sorted_pairs)
        return hashlib.sha3_256(concat.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> CorpusManifest:
        return cls(
            corpus_id=data["corpus_id"],
            name=data["name"],
            created_at=data["created_at"],
            chunk_count=data["chunk_count"],
            chunk_hashes=[tuple(p) for p in data["chunk_hashes"]],
            root=data["root"],
            signer_did=data["signer_did"],
            algorithm=data["algorithm"],
            signature=data["signature"],
            public_key=data["public_key"],
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class Corpus:
    """High-level wrapper: sign a whole corpus, produce a manifest.

    Usage:
        identity = AgentIdentity.create("rag-ingestion")
        corpus = Corpus(name="company-docs", identity=identity)
        corpus.add_document("handbook.pdf", chunks=["...", "...", "..."])
        corpus.add_document("policies.pdf", chunks=["...", "..."])
        signed_chunks = corpus.sign_all()
        manifest = corpus.build_manifest()
        # persist signed_chunks to vector DB and manifest.to_json() to disk/S3
    """

    def __init__(
        self,
        name: str,
        identity: AgentIdentity,
        corpus_id: str | None = None,
    ) -> None:
        self.corpus_id = corpus_id or f"corpus-{uuid.uuid4().hex[:12]}"
        self.name = name
        self.identity = identity
        self._documents: list[tuple[str, list[str]]] = []
        self._signed: list[SignedChunk] = []

    def add_document(self, source: str, chunks: list[str]) -> None:
        """Queue a document for signing."""
        self._documents.append((source, chunks))

    def sign_all(self) -> list[SignedChunk]:
        """Sign every queued chunk. Returns the full list of signed envelopes."""
        signer = ChunkSigner(self.identity, corpus_id=self.corpus_id)
        out: list[SignedChunk] = []
        for source, chunks in self._documents:
            out.extend(signer.sign_chunks(chunks, source=source))
        self._signed = out
        return out

    def build_manifest(self, chunks: list[SignedChunk] | None = None) -> CorpusManifest:
        """Build a signed manifest committing to all chunks in the corpus."""
        chunks = chunks if chunks is not None else self._signed
        if not chunks:
            raise CorpusIntegrityError("no chunks to build manifest from")

        chunk_hashes = [(c.chunk_id, c.content_hash) for c in chunks]
        root = CorpusManifest.compute_root(chunk_hashes)
        sig = sign(bytes.fromhex(root), self.identity.signing_keypair)
        return CorpusManifest(
            corpus_id=self.corpus_id,
            name=self.name,
            created_at=datetime.now(timezone.utc).isoformat(),
            chunk_count=len(chunks),
            chunk_hashes=sorted(chunk_hashes, key=lambda p: p[0]),
            root=root,
            signer_did=self.identity.did,
            algorithm=self.identity.signing_keypair.algorithm.value,
            signature=sig.hex(),
            public_key=self.identity.signing_keypair.public_key.hex(),
        )

    @staticmethod
    def verify_manifest(manifest: CorpusManifest) -> bool:
        """Verify the manifest root signature and recompute the root."""
        expected = CorpusManifest.compute_root(manifest.chunk_hashes)
        if expected != manifest.root:
            return False
        try:
            algorithm = SignatureAlgorithm(manifest.algorithm)
        except ValueError:
            return False
        return verify(
            bytes.fromhex(manifest.root),
            bytes.fromhex(manifest.signature),
            bytes.fromhex(manifest.public_key),
            algorithm,
        )

    @staticmethod
    def verify_chunks_against_manifest(
        chunks: Iterable[SignedChunk],
        manifest: CorpusManifest,
    ) -> tuple[bool, list[str]]:
        """Check that every chunk's (chunk_id, content_hash) is in the manifest.

        Returns (all_present, missing_chunk_ids).
        """
        manifest_pairs = {tuple(p) for p in manifest.chunk_hashes}
        missing: list[str] = []
        for c in chunks:
            pair = (c.chunk_id, c.content_hash)
            if pair not in manifest_pairs:
                missing.append(c.chunk_id)
        return len(missing) == 0, missing
