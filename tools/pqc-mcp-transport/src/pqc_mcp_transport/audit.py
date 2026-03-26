"""Audit logging for PQC MCP Transport operations."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone


@dataclass
class AuditEntry:
    """A single entry in the PQC audit log."""

    timestamp: str
    session_id: str
    operation: str  # 'handshake', 'tool_call', 'tool_response', 'verify'
    method: str | None
    signer_did: str
    peer_did: str | None
    algorithm: str
    signature_truncated: str  # first 32 chars of hex signature
    verified: bool
    details: str | None = None


class AuditLog:
    """Thread-safe audit log for PQC operations."""

    def __init__(self, max_entries: int = 10000) -> None:
        self._entries: list[AuditEntry] = []
        self._max = max_entries

    def log(self, entry: AuditEntry) -> None:
        """Append an audit entry, evicting oldest if at capacity."""
        if len(self._entries) >= self._max:
            self._entries.pop(0)
        self._entries.append(entry)

    def get_entries(
        self,
        limit: int = 100,
        signer_did: str | None = None,
    ) -> list[AuditEntry]:
        """Return recent audit entries, optionally filtered by signer DID."""
        entries = self._entries
        if signer_did is not None:
            entries = [e for e in entries if e.signer_did == signer_did]
        return entries[-limit:]

    def export_json(self) -> str:
        """Export the full audit log as a JSON string."""
        return json.dumps([asdict(e) for e in self._entries], indent=2)

    def clear(self) -> None:
        """Remove all entries from the log."""
        self._entries.clear()
