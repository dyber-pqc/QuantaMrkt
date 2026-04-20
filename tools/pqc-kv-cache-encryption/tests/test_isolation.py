"""Tests for TenantIsolationManager."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from pqc_kv_cache.errors import TenantIsolationError, UnknownTenantError
from pqc_kv_cache.isolation import TenantIsolationManager


def test_create_session_stores_by_tenant(tenant_alice) -> None:
    mgr = TenantIsolationManager()
    s = mgr.create_session(tenant_alice)
    assert mgr.sessions[tenant_alice.tenant_id] is s
    # Re-create returns same valid session
    s2 = mgr.create_session(tenant_alice)
    assert s2 is s


def test_get_session_unknown_raises() -> None:
    mgr = TenantIsolationManager()
    with pytest.raises(UnknownTenantError):
        mgr.get_session("no-such-tenant")


def test_manager_encrypt_decrypt_roundtrip(
    tenant_alice, sample_entry_factory
) -> None:
    mgr = TenantIsolationManager()
    session = mgr.create_session(tenant_alice)
    entry = sample_entry_factory(session, 1, 2)
    enc = mgr.encrypt(tenant_alice.tenant_id, entry)
    dec = mgr.decrypt(tenant_alice.tenant_id, enc)
    assert dec.key_tensor_bytes == entry.key_tensor_bytes
    assert dec.value_tensor_bytes == entry.value_tensor_bytes


def test_decrypt_alice_entry_with_bob_session_raises(
    tenant_alice, tenant_bob, sample_entry_factory
) -> None:
    mgr = TenantIsolationManager()
    session_a = mgr.create_session(tenant_alice)
    mgr.create_session(tenant_bob)
    entry = sample_entry_factory(session_a, 0, 0)
    enc = mgr.encrypt(tenant_alice.tenant_id, entry)
    # Bob's session tries to decrypt Alice's ciphertext
    with pytest.raises(TenantIsolationError):
        mgr.decrypt(tenant_bob.tenant_id, enc)


def test_list_active_tenants_excludes_expired(tenant_alice, tenant_bob) -> None:
    mgr = TenantIsolationManager()
    s_a = mgr.create_session(tenant_alice)
    mgr.create_session(tenant_bob)
    # Expire Alice's session manually
    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    s_a.expires_at = past.isoformat()
    active = mgr.list_active_tenants()
    assert tenant_bob.tenant_id in active
    assert tenant_alice.tenant_id not in active
