"""Multi-tenant isolation example.

Demonstrates:
  - Two tenants (Alice and Bob) share the same inference process.
  - Each has their own TenantSession managed by TenantIsolationManager.
  - Alice tries to decrypt Bob's cache entry via her session -> rejected.
  - Violation is logged to the audit trail.
"""

from __future__ import annotations

import os

from pqc_kv_cache import (
    EntryMetadata,
    KVAuditLog,
    KVCacheEntry,
    TenantIdentity,
    TenantIsolationError,
    TenantIsolationManager,
)


def make_entry(tenant_id: str, session_id: str, pos: int) -> KVCacheEntry:
    meta = EntryMetadata(
        tenant_id=tenant_id,
        session_id=session_id,
        layer_idx=0,
        position=pos,
        token_id=100 + pos,
    )
    return KVCacheEntry(
        metadata=meta,
        key_tensor_bytes=os.urandom(32),
        value_tensor_bytes=os.urandom(32),
    )


def main() -> None:
    mgr = TenantIsolationManager()
    audit = KVAuditLog()

    alice = TenantIdentity(tenant_id="tenant-alice", display_name="Alice Inc.")
    bob = TenantIdentity(tenant_id="tenant-bob", display_name="Bob LLC")

    s_alice = mgr.create_session(alice)
    s_bob = mgr.create_session(bob)
    print(f"Alice session: {s_alice.session_id}")
    print(f"Bob   session: {s_bob.session_id}")
    print(f"Active tenants: {mgr.list_active_tenants()}")

    # Each tenant encrypts their own KV entry
    alice_entry = make_entry(alice.tenant_id, s_alice.session_id, pos=0)
    bob_entry = make_entry(bob.tenant_id, s_bob.session_id, pos=0)

    alice_enc = mgr.encrypt(alice.tenant_id, alice_entry)
    bob_enc = mgr.encrypt(bob.tenant_id, bob_entry)
    print("Alice encrypted her entry.")
    print("Bob   encrypted his entry.")

    # Alice attempts to decrypt Bob's ciphertext through her session
    try:
        mgr.decrypt(alice.tenant_id, bob_enc)
    except TenantIsolationError as exc:
        print(f"\nExpected isolation violation: {exc}")
        audit.log_isolation_violation(
            attacker_tenant=alice.tenant_id,
            target_tenant=bob.tenant_id,
            details="attempted cross-tenant decrypt",
        )

    # Alice can still decrypt her own
    dec_a = mgr.decrypt(alice.tenant_id, alice_enc)
    assert dec_a.key_tensor_bytes == alice_entry.key_tensor_bytes
    print("Alice successfully decrypted her own entry.")

    # Bob can still decrypt his own
    dec_b = mgr.decrypt(bob.tenant_id, bob_enc)
    assert dec_b.value_tensor_bytes == bob_entry.value_tensor_bytes
    print("Bob   successfully decrypted his own entry.")

    print("\nIsolation audit entries:")
    for entry in audit.entries(operation="isolation-violation"):
        print(f"  {entry.timestamp} attacker={entry.tenant_id} {entry.details}")


if __name__ == "__main__":
    main()
