"""Audit log for wallet operations. ML-DSA signed entries."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.signatures import sign, verify
from quantumshield.identity.agent import AgentIdentity


@dataclass
class WalletAuditEntry:
    """One audit event: who did what, signed with ML-DSA."""

    timestamp: str
    operation: str  # 'unlock' | 'lock' | 'put' | 'get' | 'delete' | 'rotate'
    actor_did: str
    credential_name: str
    success: bool
    details: str = ""
    signer_did: str = ""
    algorithm: str = ""
    signature: str = ""  # hex

    def canonical_bytes(self) -> bytes:
        """Bytes used for signing (no signature fields)."""
        payload = {
            "timestamp": self.timestamp,
            "operation": self.operation,
            "actor_did": self.actor_did,
            "credential_name": self.credential_name,
            "success": self.success,
            "details": self.details,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def sign(self, identity: AgentIdentity) -> None:
        """Sign this entry in place."""
        canonical = self.canonical_bytes()
        digest = hashlib.sha3_256(canonical).digest()
        sig = sign(digest, identity.signing_keypair)
        self.signer_did = identity.did
        self.algorithm = identity.signing_keypair.algorithm.value
        self.signature = sig.hex()

    def verify_signature(self, public_key_hex: str) -> bool:
        if not self.signature:
            return False
        try:
            algorithm = SignatureAlgorithm(self.algorithm)
        except ValueError:
            return False
        digest = hashlib.sha3_256(self.canonical_bytes()).digest()
        try:
            return verify(
                digest,
                bytes.fromhex(self.signature),
                bytes.fromhex(public_key_hex),
                algorithm,
            )
        except Exception:
            return False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WalletAuditEntry:
        return cls(**data)


class WalletAuditLog:
    """Append-only in-memory audit log. Production should persist entries."""

    def __init__(self, max_entries: int = 100_000) -> None:
        self._entries: list[WalletAuditEntry] = []
        self._max = max_entries

    def log(
        self,
        operation: str,
        actor: AgentIdentity,
        credential_name: str,
        success: bool,
        details: str = "",
    ) -> WalletAuditEntry:
        entry = WalletAuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            operation=operation,
            actor_did=actor.did,
            credential_name=credential_name,
            success=success,
            details=details,
        )
        entry.sign(actor)
        if len(self._entries) >= self._max:
            self._entries.pop(0)
        self._entries.append(entry)
        return entry

    def entries(
        self,
        limit: int = 100,
        operation: str | None = None,
        credential_name: str | None = None,
    ) -> list[WalletAuditEntry]:
        out = self._entries
        if operation:
            out = [e for e in out if e.operation == operation]
        if credential_name:
            out = [e for e in out if e.credential_name == credential_name]
        return out[-limit:][::-1]

    def export_json(self) -> str:
        return json.dumps([e.to_dict() for e in self._entries], indent=2)

    def clear(self) -> None:
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)
