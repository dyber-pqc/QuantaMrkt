"""PQC Memory Encryption for LLM KV Cache - per-tenant quantum-safe cache."""

from pqc_kv_cache.audit import KVAuditEntry, KVAuditLog
from pqc_kv_cache.encryptor import CacheDecryptor, CacheEncryptor
from pqc_kv_cache.entry import EncryptedEntry, EntryMetadata, KVCacheEntry
from pqc_kv_cache.errors import (
    DecryptionError,
    KeyRotationRequiredError,
    KVCacheError,
    NonceReplayError,
    SessionExpiredError,
    TenantIsolationError,
    UnknownTenantError,
)
from pqc_kv_cache.isolation import TenantIsolationManager
from pqc_kv_cache.rotation import KeyRotationPolicy, RotationTrigger
from pqc_kv_cache.session import (
    TenantIdentity,
    TenantSession,
    establish_tenant_session,
)

__version__ = "0.1.0"
__all__ = [
    "KVCacheEntry", "EncryptedEntry", "EntryMetadata",
    "TenantSession", "TenantIdentity", "establish_tenant_session",
    "CacheEncryptor", "CacheDecryptor",
    "KeyRotationPolicy", "RotationTrigger",
    "TenantIsolationManager",
    "KVAuditLog", "KVAuditEntry",
    "KVCacheError", "TenantIsolationError", "SessionExpiredError",
    "DecryptionError", "NonceReplayError", "KeyRotationRequiredError",
    "UnknownTenantError",
]
