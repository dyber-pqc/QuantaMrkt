"""TenantIsolationManager - supervises multiple TenantSessions simultaneously."""

from __future__ import annotations

from dataclasses import dataclass, field

from pqc_kv_cache.encryptor import CacheDecryptor, CacheEncryptor
from pqc_kv_cache.entry import EncryptedEntry, KVCacheEntry
from pqc_kv_cache.errors import TenantIsolationError, UnknownTenantError
from pqc_kv_cache.session import (
    TenantIdentity,
    TenantSession,
    establish_tenant_session,
)


@dataclass
class TenantIsolationManager:
    """Manages multiple TenantSessions and enforces strict isolation."""

    sessions: dict[str, TenantSession] = field(default_factory=dict)

    def create_session(self, tenant: TenantIdentity) -> TenantSession:
        if (
            tenant.tenant_id in self.sessions
            and self.sessions[tenant.tenant_id].is_valid()
        ):
            return self.sessions[tenant.tenant_id]
        session = establish_tenant_session(tenant)
        self.sessions[tenant.tenant_id] = session
        return session

    def get_session(self, tenant_id: str) -> TenantSession:
        if tenant_id not in self.sessions:
            raise UnknownTenantError(f"no session for tenant {tenant_id}")
        return self.sessions[tenant_id]

    def encrypt(self, tenant_id: str, entry: KVCacheEntry) -> EncryptedEntry:
        session = self.get_session(tenant_id)
        if entry.metadata.tenant_id != tenant_id:
            raise TenantIsolationError(
                f"entry tenant {entry.metadata.tenant_id} != provided tenant {tenant_id}"
            )
        return CacheEncryptor(session).encrypt_entry(entry)

    def decrypt(self, tenant_id: str, enc: EncryptedEntry) -> KVCacheEntry:
        session = self.get_session(tenant_id)
        return CacheDecryptor(session).decrypt_entry(enc)

    def close_session(self, tenant_id: str) -> None:
        self.sessions.pop(tenant_id, None)

    def list_active_tenants(self) -> list[str]:
        return [tid for tid, s in self.sessions.items() if s.is_valid()]
