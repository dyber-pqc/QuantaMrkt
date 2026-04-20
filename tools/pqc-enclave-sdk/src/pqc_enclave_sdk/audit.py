"""Append-only audit log for enclave operations."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass
class EnclaveAuditEntry:
    """One audit event: who did what, to which artifact, when."""

    timestamp: str
    operation: str  # 'unlock' | 'lock' | 'put' | 'get' | 'delete' | 'policy_violation' | 'attest'
    device_id: str
    artifact_id: str = ""
    artifact_name: str = ""
    artifact_kind: str = ""
    success: bool = True
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EnclaveAuditEntry:
        return cls(**data)


class EnclaveAuditLog:
    """Append-only in-memory audit log. Production should persist entries."""

    def __init__(self, max_entries: int = 100_000) -> None:
        self._entries: list[EnclaveAuditEntry] = []
        self._max = max_entries

    def _append(self, entry: EnclaveAuditEntry) -> EnclaveAuditEntry:
        if len(self._entries) >= self._max:
            self._entries.pop(0)
        self._entries.append(entry)
        return entry

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # -- operation-specific log helpers ------------------------------------

    def log_unlock(self, device_id: str, key_id: str) -> EnclaveAuditEntry:
        return self._append(
            EnclaveAuditEntry(
                timestamp=self._now(),
                operation="unlock",
                device_id=device_id,
                success=True,
                details=f"key_id={key_id}",
            )
        )

    def log_lock(self, device_id: str) -> EnclaveAuditEntry:
        return self._append(
            EnclaveAuditEntry(
                timestamp=self._now(),
                operation="lock",
                device_id=device_id,
                success=True,
            )
        )

    def log_put(
        self, device_id: str, artifact_id: str, artifact_name: str, artifact_kind: str
    ) -> EnclaveAuditEntry:
        return self._append(
            EnclaveAuditEntry(
                timestamp=self._now(),
                operation="put",
                device_id=device_id,
                artifact_id=artifact_id,
                artifact_name=artifact_name,
                artifact_kind=artifact_kind,
                success=True,
            )
        )

    def log_get(
        self,
        device_id: str,
        artifact_id: str,
        success: bool = True,
        details: str = "",
    ) -> EnclaveAuditEntry:
        return self._append(
            EnclaveAuditEntry(
                timestamp=self._now(),
                operation="get",
                device_id=device_id,
                artifact_id=artifact_id,
                success=success,
                details=details,
            )
        )

    def log_delete(
        self, device_id: str, artifact_id: str, artifact_name: str
    ) -> EnclaveAuditEntry:
        return self._append(
            EnclaveAuditEntry(
                timestamp=self._now(),
                operation="delete",
                device_id=device_id,
                artifact_id=artifact_id,
                artifact_name=artifact_name,
                success=True,
            )
        )

    def log_policy_violation(
        self, device_id: str, artifact_id: str, details: str
    ) -> EnclaveAuditEntry:
        return self._append(
            EnclaveAuditEntry(
                timestamp=self._now(),
                operation="policy_violation",
                device_id=device_id,
                artifact_id=artifact_id,
                success=False,
                details=details,
            )
        )

    def log_attest(
        self, device_id: str, artifact_id: str, details: str = ""
    ) -> EnclaveAuditEntry:
        return self._append(
            EnclaveAuditEntry(
                timestamp=self._now(),
                operation="attest",
                device_id=device_id,
                artifact_id=artifact_id,
                success=True,
                details=details,
            )
        )

    # -- query -------------------------------------------------------------

    def entries(
        self,
        limit: int = 100,
        operation: str | None = None,
        device_id: str | None = None,
        artifact_id: str | None = None,
    ) -> list[EnclaveAuditEntry]:
        out = self._entries
        if operation:
            out = [e for e in out if e.operation == operation]
        if device_id:
            out = [e for e in out if e.device_id == device_id]
        if artifact_id:
            out = [e for e in out if e.artifact_id == artifact_id]
        return out[-limit:][::-1]

    def export_json(self) -> str:
        return json.dumps([e.to_dict() for e in self._entries], indent=2)

    def clear(self) -> None:
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)
