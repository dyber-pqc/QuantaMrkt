"""Exception hierarchy for pqc-kv-cache-encryption."""

from __future__ import annotations


class KVCacheError(Exception):
    """Base exception for all pqc-kv-cache-encryption errors."""


class TenantIsolationError(KVCacheError):
    """Raised when an operation would cross a tenant boundary.

    This includes attempts to encrypt an entry whose metadata tenant_id does
    not match the session tenant, or attempts to decrypt another tenant's
    EncryptedEntry with the wrong session.
    """


class SessionExpiredError(KVCacheError):
    """Raised when a TenantSession's TTL has elapsed."""


class DecryptionError(KVCacheError):
    """Raised when AES-256-GCM decryption fails (bad tag, tampered AAD, etc.)."""


class NonceReplayError(KVCacheError):
    """Raised when the same nonce is presented to a decryptor twice."""


class KeyRotationRequiredError(KVCacheError):
    """Raised when the rotation policy demands a new key before continuing."""


class UnknownTenantError(KVCacheError):
    """Raised when a TenantIsolationManager is asked about an unknown tenant."""
