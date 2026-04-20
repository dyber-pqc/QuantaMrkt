"""Key rotation example.

Demonstrates:
  - KeyRotationPolicy with a low entry threshold (5).
  - Encrypting 10 entries in one session.
  - Rotating the key after 5 entries.
  - Verifying the new key materially differs from the old one.
"""

from __future__ import annotations

import os

from pqc_kv_cache import (
    CacheEncryptor,
    EntryMetadata,
    KeyRotationPolicy,
    KVAuditLog,
    KVCacheEntry,
    TenantIdentity,
    establish_tenant_session,
)


def main() -> None:
    tenant = TenantIdentity(tenant_id="tenant-alice", display_name="Alice")
    session = establish_tenant_session(tenant)
    policy = KeyRotationPolicy(max_entries=5, max_age_seconds=3600)
    audit = KVAuditLog()

    original_key_prefix = session.symmetric_key[:4].hex()
    print(f"Original key prefix: {original_key_prefix}")

    rotated_once = False
    for pos in range(10):
        meta = EntryMetadata(
            tenant_id=tenant.tenant_id,
            session_id=session.session_id,
            layer_idx=0,
            position=pos,
        )
        entry = KVCacheEntry(
            metadata=meta,
            key_tensor_bytes=os.urandom(32),
            value_tensor_bytes=os.urandom(32),
        )
        enc = CacheEncryptor(session).encrypt_entry(entry)
        audit.log_encrypt(
            tenant.tenant_id,
            session.session_id,
            0,
            pos,
            enc.sequence_number,
        )
        print(
            f"pos={pos} encrypted seq={enc.sequence_number} "
            f"entries_encrypted={session.entries_encrypted}"
        )

        should, trigger = policy.should_rotate(session)
        if should and not rotated_once:
            print(f"  -> rotation triggered by {trigger.value}")
            old_key = session.symmetric_key
            new_key = policy.rotate(session)
            audit.log_rotate(tenant.tenant_id, session.session_id, trigger.value)
            assert new_key != old_key
            print(f"  -> new key prefix: {new_key[:4].hex()}")
            print(
                f"  -> session reset: entries_encrypted="
                f"{session.entries_encrypted} next_sequence={session.next_sequence}"
            )
            rotated_once = True

    print("\nAudit operations:")
    for entry in audit.entries(limit=20):
        print(f"  {entry.operation:8s} seq={entry.sequence_number} details={entry.details}")


if __name__ == "__main__":
    main()
