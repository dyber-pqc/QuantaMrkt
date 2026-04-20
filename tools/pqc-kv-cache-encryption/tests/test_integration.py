"""End-to-end integration tests."""

from __future__ import annotations

import pytest

from pqc_kv_cache.audit import KVAuditLog
from pqc_kv_cache.errors import TenantIsolationError
from pqc_kv_cache.isolation import TenantIsolationManager
from pqc_kv_cache.rotation import KeyRotationPolicy, RotationTrigger


def test_multi_tenant_flow(
    tenant_alice, tenant_bob, sample_entry_factory
) -> None:
    mgr = TenantIsolationManager()
    audit = KVAuditLog()

    s_alice = mgr.create_session(tenant_alice)
    s_bob = mgr.create_session(tenant_bob)

    alice_encs = []
    bob_encs = []
    for pos in range(5):
        a_entry = sample_entry_factory(s_alice, 0, pos)
        b_entry = sample_entry_factory(s_bob, 0, pos)
        ae = mgr.encrypt(tenant_alice.tenant_id, a_entry)
        be = mgr.encrypt(tenant_bob.tenant_id, b_entry)
        audit.log_encrypt(
            tenant_alice.tenant_id, s_alice.session_id, 0, pos, ae.sequence_number
        )
        audit.log_encrypt(
            tenant_bob.tenant_id, s_bob.session_id, 0, pos, be.sequence_number
        )
        alice_encs.append(ae)
        bob_encs.append(be)

    # Alice MUST NOT be able to decrypt any of Bob's entries
    for be in bob_encs:
        with pytest.raises(TenantIsolationError):
            mgr.decrypt(tenant_alice.tenant_id, be)
        audit.log_isolation_violation(
            tenant_alice.tenant_id,
            tenant_bob.tenant_id,
            details=f"seq={be.sequence_number}",
        )

    # Alice can decrypt her own
    for ae in alice_encs:
        dec = mgr.decrypt(tenant_alice.tenant_id, ae)
        assert dec.metadata.tenant_id == tenant_alice.tenant_id

    violations = audit.entries(operation="isolation-violation")
    assert len(violations) == 5


def test_rotation_flow(tenant_alice, sample_entry_factory) -> None:
    mgr = TenantIsolationManager()
    policy = KeyRotationPolicy(max_entries=50, max_age_seconds=3600)
    session = mgr.create_session(tenant_alice)
    original_key = session.symmetric_key

    rotated = False
    for pos in range(100):
        entry = sample_entry_factory(session, 0, pos)
        mgr.encrypt(tenant_alice.tenant_id, entry)
        should, trigger = policy.should_rotate(session)
        if should and not rotated:
            assert trigger is RotationTrigger.ENTRY_COUNT
            assert pos + 1 >= 50
            policy.rotate(session)
            rotated = True
            new_key = session.symmetric_key
            assert new_key != original_key
            assert session.entries_encrypted == 0
            assert session.next_sequence == 1

    assert rotated is True
