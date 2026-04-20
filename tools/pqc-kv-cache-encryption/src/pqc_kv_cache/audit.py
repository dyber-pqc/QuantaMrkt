"""Append-only audit log for KV cache operations."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass
class KVAuditEntry:
    timestamp: str
    operation: str                 # 'encrypt' | 'decrypt' | 'rotate' | 'isolation-violation'
    tenant_id: str
    session_id: str
    layer_idx: int = -1
    position: int = -1
    sequence_number: int = -1
    success: bool = True
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class KVAuditLog:
    def __init__(self, max_entries: int = 1_000_000) -> None:
        self._entries: list[KVAuditEntry] = []
        self._max = max_entries

    def log(self, entry: KVAuditEntry) -> None:
        if len(self._entries) >= self._max:
            self._entries.pop(0)
        self._entries.append(entry)

    def log_encrypt(
        self,
        tenant_id: str,
        session_id: str,
        layer_idx: int,
        position: int,
        seq: int,
    ) -> None:
        self.log(
            KVAuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                operation="encrypt",
                tenant_id=tenant_id,
                session_id=session_id,
                layer_idx=layer_idx,
                position=position,
                sequence_number=seq,
                success=True,
            )
        )

    def log_decrypt(
        self,
        tenant_id: str,
        session_id: str,
        layer_idx: int,
        position: int,
        seq: int,
        success: bool,
        details: str = "",
    ) -> None:
        self.log(
            KVAuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                operation="decrypt",
                tenant_id=tenant_id,
                session_id=session_id,
                layer_idx=layer_idx,
                position=position,
                sequence_number=seq,
                success=success,
                details=details,
            )
        )

    def log_rotate(self, tenant_id: str, session_id: str, trigger: str) -> None:
        self.log(
            KVAuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                operation="rotate",
                tenant_id=tenant_id,
                session_id=session_id,
                success=True,
                details=f"trigger={trigger}",
            )
        )

    def log_isolation_violation(
        self, attacker_tenant: str, target_tenant: str, details: str = ""
    ) -> None:
        self.log(
            KVAuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                operation="isolation-violation",
                tenant_id=attacker_tenant,
                session_id="",
                success=False,
                details=f"target={target_tenant}; {details}",
            )
        )

    def entries(
        self,
        limit: int = 100,
        tenant_id: str | None = None,
        operation: str | None = None,
    ) -> list[KVAuditEntry]:
        out = self._entries
        if tenant_id:
            out = [e for e in out if e.tenant_id == tenant_id]
        if operation:
            out = [e for e in out if e.operation == operation]
        return out[-limit:][::-1]

    def export_json(self) -> str:
        return json.dumps([e.to_dict() for e in self._entries], indent=2)

    def __len__(self) -> int:
        return len(self._entries)
