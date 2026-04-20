"""CacheEncryptor / CacheDecryptor - the AES-256-GCM wrappers."""

from __future__ import annotations

import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pqc_kv_cache.entry import EncryptedEntry, EntryMetadata, KVCacheEntry
from pqc_kv_cache.errors import (
    DecryptionError,
    NonceReplayError,
    TenantIsolationError,
)
from pqc_kv_cache.session import TenantSession

NONCE_SIZE = 12


def _aad(metadata: EntryMetadata, sequence_number: int, key_len: int) -> bytes:
    """Associated data binding metadata + sequence + key_len to the ciphertext."""
    payload = {
        "metadata": metadata.to_dict(),
        "sequence_number": sequence_number,
        "key_len": key_len,
    }
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


class CacheEncryptor:
    """Wraps a TenantSession to produce EncryptedEntry objects."""

    def __init__(self, session: TenantSession):
        self.session = session

    def encrypt_entry(self, entry: KVCacheEntry) -> EncryptedEntry:
        self.session.check_valid()
        if entry.metadata.tenant_id != self.session.tenant.tenant_id:
            raise TenantIsolationError(
                f"entry tenant {entry.metadata.tenant_id} != session tenant "
                f"{self.session.tenant.tenant_id}"
            )
        seq = self.session.consume_sequence()
        nonce = os.urandom(NONCE_SIZE)
        plaintext = entry.key_tensor_bytes + entry.value_tensor_bytes
        key_len = len(entry.key_tensor_bytes)
        aad = _aad(entry.metadata, seq, key_len)
        aes = AESGCM(self.session.symmetric_key)
        ct = aes.encrypt(nonce, plaintext, aad)
        return EncryptedEntry(
            metadata=entry.metadata,
            nonce=nonce.hex(),
            ciphertext=ct.hex(),
            key_len=key_len,
            sequence_number=seq,
        )


class CacheDecryptor:
    """Wraps a TenantSession to decrypt EncryptedEntry objects.

    Enforces strict tenant isolation: refuses to decrypt entries whose
    metadata.tenant_id does not match the session's tenant_id, even if the
    symmetric key would somehow work.
    """

    def __init__(self, session: TenantSession):
        self.session = session
        self._seen_nonces: set[str] = set()

    def decrypt_entry(self, enc: EncryptedEntry) -> KVCacheEntry:
        self.session.check_valid()
        if enc.metadata.tenant_id != self.session.tenant.tenant_id:
            raise TenantIsolationError(
                f"entry tenant {enc.metadata.tenant_id} != session tenant "
                f"{self.session.tenant.tenant_id}"
            )
        if enc.nonce in self._seen_nonces:
            raise NonceReplayError(f"nonce {enc.nonce} already consumed")
        aad = _aad(enc.metadata, enc.sequence_number, enc.key_len)
        aes = AESGCM(self.session.symmetric_key)
        try:
            pt = aes.decrypt(
                bytes.fromhex(enc.nonce), bytes.fromhex(enc.ciphertext), aad
            )
        except Exception as exc:
            raise DecryptionError(f"AES-GCM decrypt failed: {exc}") from exc
        self._seen_nonces.add(enc.nonce)
        key_bytes = pt[: enc.key_len]
        val_bytes = pt[enc.key_len:]
        return KVCacheEntry(
            metadata=enc.metadata,
            key_tensor_bytes=key_bytes,
            value_tensor_bytes=val_bytes,
        )
