"""TenantSession - per-tenant symmetric key derived from ML-KEM-768."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from quantumshield.core.algorithms import KEMAlgorithm
from quantumshield.core.keys import generate_kem_keypair

from pqc_kv_cache.errors import SessionExpiredError

SESSION_TTL_SECONDS = 900       # 15 minutes default


@dataclass(frozen=True)
class TenantIdentity:
    """Identifier for a tenant (user/org/session)."""

    tenant_id: str
    display_name: str = ""


def establish_tenant_session(
    tenant: TenantIdentity,
    algorithm: KEMAlgorithm = KEMAlgorithm.ML_KEM_768,
    ttl_seconds: int = SESSION_TTL_SECONDS,
) -> TenantSession:
    """Derive a fresh per-tenant session key via ML-KEM-768.

    In production: the tenant supplies their KEM public key and the inference
    server runs Encapsulate to derive the shared symmetric key. Here we
    generate a fresh keypair and derive a 32-byte AES key deterministically
    from the keypair so the pattern works under the Ed25519 fallback backend.
    """
    kp = generate_kem_keypair(algorithm)
    # Deterministic derivation from the keypair's raw bytes
    symmetric_key = hashlib.sha3_256(kp.private_key + kp.public_key).digest()
    session_id = f"urn:pqc-kv-sess:{uuid.uuid4().hex}"
    now = datetime.now(timezone.utc)
    exp = now + timedelta(seconds=ttl_seconds)
    return TenantSession(
        session_id=session_id,
        tenant=tenant,
        symmetric_key=symmetric_key,
        algorithm=algorithm.value,
        created_at=now.isoformat(),
        expires_at=exp.isoformat(),
    )


@dataclass
class TenantSession:
    """Per-tenant session holding the AES-256-GCM key + counters."""

    session_id: str
    tenant: TenantIdentity
    symmetric_key: bytes
    algorithm: str
    created_at: str
    expires_at: str
    next_sequence: int = 1
    entries_encrypted: int = 0

    def is_valid(self) -> bool:
        try:
            exp = datetime.fromisoformat(self.expires_at)
            return datetime.now(timezone.utc) <= exp
        except ValueError:
            return False

    def check_valid(self) -> None:
        if not self.is_valid():
            raise SessionExpiredError(f"session {self.session_id} expired")

    def consume_sequence(self) -> int:
        seq = self.next_sequence
        self.next_sequence += 1
        self.entries_encrypted += 1
        return seq

    def rotate_key(self, new_key: bytes) -> None:
        """Replace the symmetric key (used by KeyRotationPolicy)."""
        self.symmetric_key = new_key
        self.next_sequence = 1
        self.entries_encrypted = 0

    def to_public_dict(self) -> dict[str, Any]:
        """Serialize without the symmetric key - safe for logs/telemetry."""
        return {
            "session_id": self.session_id,
            "tenant_id": self.tenant.tenant_id,
            "tenant_display": self.tenant.display_name,
            "algorithm": self.algorithm,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "entries_encrypted": self.entries_encrypted,
            "is_valid": self.is_valid(),
        }
