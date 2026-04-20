"""Audit log for RAG retrieval events."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone


@dataclass
class RAGAuditEntry:
    """A single RAG retrieval event logged for audit."""

    timestamp: str
    operation: str
    corpus_id: str | None
    chunk_id: str | None
    signer_did: str | None
    algorithm: str | None
    verified: bool
    query_hash: str | None = None
    details: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class RAGAuditLog:
    """Append-only audit log for RAG operations.

    Production usage: persist entries to a real log backend. This class gives
    you an in-memory structure with export for integrations.
    """

    def __init__(self, max_entries: int = 100_000) -> None:
        self._entries: list[RAGAuditEntry] = []
        self._max = max_entries

    def log(self, entry: RAGAuditEntry) -> None:
        if len(self._entries) >= self._max:
            self._entries.pop(0)
        self._entries.append(entry)

    def log_sign(
        self,
        corpus_id: str,
        chunk_id: str,
        signer_did: str,
        algorithm: str,
    ) -> None:
        self.log(
            RAGAuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                operation="sign_chunk",
                corpus_id=corpus_id,
                chunk_id=chunk_id,
                signer_did=signer_did,
                algorithm=algorithm,
                verified=True,
            )
        )

    def log_verify(
        self,
        chunk_id: str,
        signer_did: str | None,
        algorithm: str | None,
        verified: bool,
        details: str | None = None,
    ) -> None:
        self.log(
            RAGAuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                operation="verify_chunk",
                corpus_id=None,
                chunk_id=chunk_id,
                signer_did=signer_did,
                algorithm=algorithm,
                verified=verified,
                details=details,
            )
        )

    def log_retrieval(
        self,
        query_hash: str,
        verified_count: int,
        failed_count: int,
    ) -> None:
        self.log(
            RAGAuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                operation="retrieve",
                corpus_id=None,
                chunk_id=None,
                signer_did=None,
                algorithm=None,
                verified=failed_count == 0,
                query_hash=query_hash,
                details=f"{verified_count} verified, {failed_count} failed",
            )
        )

    def entries(
        self,
        limit: int = 100,
        operation: str | None = None,
        signer_did: str | None = None,
    ) -> list[RAGAuditEntry]:
        filtered = self._entries
        if operation:
            filtered = [e for e in filtered if e.operation == operation]
        if signer_did:
            filtered = [e for e in filtered if e.signer_did == signer_did]
        return filtered[-limit:][::-1]

    def export_json(self) -> str:
        return json.dumps([e.to_dict() for e in self._entries], indent=2)

    def clear(self) -> None:
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)
