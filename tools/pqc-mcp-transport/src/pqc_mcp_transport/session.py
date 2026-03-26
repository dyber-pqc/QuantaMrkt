"""PQC session management with replay protection and audit logging."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.identity.agent import AgentIdentity

from pqc_mcp_transport.audit import AuditEntry
from pqc_mcp_transport.errors import ReplayAttackError, SessionExpiredError


@dataclass
class PQCSession:
    """An authenticated PQC session between two MCP peers."""

    session_id: str
    local_identity: AgentIdentity
    peer_did: str
    peer_public_key: bytes
    peer_algorithm: SignatureAlgorithm
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(hours=1)
    )
    _used_nonces: set[str] = field(default_factory=set)
    _audit_log: list[AuditEntry] = field(default_factory=list)
    last_response_verified: bool = False

    def is_valid(self) -> bool:
        """Return True if the session has not expired."""
        return datetime.now(timezone.utc) < self.expires_at

    def check_nonce(self, nonce: str) -> bool:
        """Check and register a nonce for replay protection.

        Returns True if the nonce is fresh.  Raises :class:`ReplayAttackError`
        if the nonce has already been seen.
        """
        if nonce in self._used_nonces:
            raise ReplayAttackError(f"Nonce already used: {nonce}")
        self._used_nonces.add(nonce)
        return True

    def log_operation(
        self,
        op_type: str,
        method: str | None,
        signer_did: str,
        verified: bool,
        signature_hex: str = "",
        algorithm: str = "",
        details: str | None = None,
    ) -> None:
        """Record an operation in the session audit log."""
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            session_id=self.session_id,
            operation=op_type,
            method=method,
            signer_did=signer_did,
            peer_did=self.peer_did,
            algorithm=algorithm or self.peer_algorithm.value,
            signature_truncated=signature_hex[:32] if signature_hex else "",
            verified=verified,
            details=details,
        )
        self._audit_log.append(entry)

    def get_audit_log(self) -> list[AuditEntry]:
        """Return the full audit trail for this session."""
        return list(self._audit_log)
