"""Append-only audit log for eBPF load attempts."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from pqc_ebpf_attestation.policy import PolicyDecision
from pqc_ebpf_attestation.signer import SignedBPFProgram


@dataclass
class AttestationLogEntry:
    timestamp: str
    program_name: str
    program_type: str
    bytecode_hash: str
    signer_did: str
    decision: str  # "allow" | "deny"
    reason: str
    actor: str = ""  # who initiated the load (user/service)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AttestationLog:
    """Append-only in-memory log of eBPF load decisions."""

    def __init__(self, max_entries: int = 100_000) -> None:
        self._entries: list[AttestationLogEntry] = []
        self._max = max_entries

    def log(
        self,
        signed: SignedBPFProgram,
        decision: PolicyDecision,
        reason: str,
        actor: str = "",
    ) -> AttestationLogEntry:
        entry = AttestationLogEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            program_name=signed.program.metadata.name,
            program_type=signed.program.metadata.program_type.value,
            bytecode_hash=signed.program.bytecode_hash,
            signer_did=signed.signer_did,
            decision=decision.value,
            reason=reason,
            actor=actor,
        )
        if len(self._entries) >= self._max:
            self._entries.pop(0)
        self._entries.append(entry)
        return entry

    def entries(
        self,
        limit: int = 100,
        decision: str | None = None,
        signer_did: str | None = None,
    ) -> list[AttestationLogEntry]:
        out = self._entries
        if decision:
            out = [e for e in out if e.decision == decision]
        if signer_did:
            out = [e for e in out if e.signer_did == signer_did]
        return out[-limit:][::-1]

    def export_json(self) -> str:
        return json.dumps([e.to_dict() for e in self._entries], indent=2)

    def __len__(self) -> int:
        return len(self._entries)
