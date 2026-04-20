"""Append-only log of boot attempts."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass
class BootAttemptEntry:
    timestamp: str
    firmware_name: str
    firmware_version: str
    firmware_hash: str
    decision: str  # "accept" | "reject"
    reason: str
    device_id: str = ""  # identifier of the appliance
    pcr_value_after: str = ""  # final PCR after measurements (if captured)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BootAttestationLog:
    def __init__(self, max_entries: int = 100_000) -> None:
        self._entries: list[BootAttemptEntry] = []
        self._max = max_entries

    def log_accept(
        self,
        firmware_name: str,
        firmware_version: str,
        firmware_hash: str,
        reason: str = "",
        device_id: str = "",
        pcr_value_after: str = "",
    ) -> BootAttemptEntry:
        entry = BootAttemptEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            firmware_name=firmware_name,
            firmware_version=firmware_version,
            firmware_hash=firmware_hash,
            decision="accept",
            reason=reason or "all checks passed",
            device_id=device_id,
            pcr_value_after=pcr_value_after,
        )
        self._append(entry)
        return entry

    def log_reject(
        self,
        firmware_name: str,
        firmware_version: str,
        firmware_hash: str,
        reason: str,
        device_id: str = "",
    ) -> BootAttemptEntry:
        entry = BootAttemptEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            firmware_name=firmware_name,
            firmware_version=firmware_version,
            firmware_hash=firmware_hash,
            decision="reject",
            reason=reason,
            device_id=device_id,
        )
        self._append(entry)
        return entry

    def _append(self, entry: BootAttemptEntry) -> None:
        if len(self._entries) >= self._max:
            self._entries.pop(0)
        self._entries.append(entry)

    def entries(
        self,
        limit: int = 100,
        decision: str | None = None,
    ) -> list[BootAttemptEntry]:
        out = self._entries
        if decision:
            out = [e for e in out if e.decision == decision]
        return out[-limit:][::-1]

    def export_json(self) -> str:
        return json.dumps([e.to_dict() for e in self._entries], indent=2)

    def __len__(self) -> int:
        return len(self._entries)
