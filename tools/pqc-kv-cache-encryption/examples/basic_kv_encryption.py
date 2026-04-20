"""Basic single-tenant KV cache encryption example.

Demonstrates:
  1. Establishing a TenantSession for one tenant.
  2. Encrypting 3 KV cache entries (simulating 3 token positions).
  3. Decrypting them back and verifying round-trip.
  4. Printing the audit log.
"""

from __future__ import annotations

import os

from pqc_kv_cache import (
    CacheDecryptor,
    CacheEncryptor,
    EntryMetadata,
    KVAuditLog,
    KVCacheEntry,
    TenantIdentity,
    establish_tenant_session,
)


def main() -> None:
    tenant = TenantIdentity(tenant_id="tenant-alice", display_name="Alice Corp")
    session = establish_tenant_session(tenant)
    print(f"Session established: {session.session_id}")
    print(f"Algorithm: {session.algorithm}")
    print(f"Expires at: {session.expires_at}")

    encryptor = CacheEncryptor(session)
    decryptor = CacheDecryptor(session)
    audit = KVAuditLog()

    # Simulate encrypting K/V for 3 token positions in layer 0
    encrypted_entries = []
    originals: list[KVCacheEntry] = []
    for pos in range(3):
        meta = EntryMetadata(
            tenant_id=tenant.tenant_id,
            session_id=session.session_id,
            layer_idx=0,
            position=pos,
            token_id=1000 + pos,
        )
        entry = KVCacheEntry(
            metadata=meta,
            key_tensor_bytes=os.urandom(64),
            value_tensor_bytes=os.urandom(64),
        )
        originals.append(entry)
        enc = encryptor.encrypt_entry(entry)
        audit.log_encrypt(
            tenant.tenant_id,
            session.session_id,
            meta.layer_idx,
            meta.position,
            enc.sequence_number,
        )
        encrypted_entries.append(enc)
        print(f"Encrypted pos={pos} seq={enc.sequence_number} ct_bytes={len(enc.ciphertext) // 2}")

    # Decrypt and verify
    for orig, enc in zip(originals, encrypted_entries):
        dec = decryptor.decrypt_entry(enc)
        assert dec.key_tensor_bytes == orig.key_tensor_bytes
        assert dec.value_tensor_bytes == orig.value_tensor_bytes
        audit.log_decrypt(
            tenant.tenant_id,
            session.session_id,
            orig.metadata.layer_idx,
            orig.metadata.position,
            enc.sequence_number,
            success=True,
        )
        print(f"Decrypted pos={orig.metadata.position} OK")

    print("\nAudit log entries:")
    for entry in audit.entries(limit=10):
        print(f"  {entry.timestamp} {entry.operation:8s} seq={entry.sequence_number}")


if __name__ == "__main__":
    main()
