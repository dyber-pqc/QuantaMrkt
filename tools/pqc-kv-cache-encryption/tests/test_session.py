"""Tests for TenantSession and establish_tenant_session."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from pqc_kv_cache.errors import SessionExpiredError
from pqc_kv_cache.session import (
    TenantIdentity,
    establish_tenant_session,
)


def test_establish_creates_valid_session() -> None:
    tenant = TenantIdentity(tenant_id="t1", display_name="T 1")
    s = establish_tenant_session(tenant)
    assert s.is_valid()
    assert len(s.symmetric_key) == 32
    assert s.tenant == tenant
    assert s.session_id.startswith("urn:pqc-kv-sess:")


def test_session_id_unique_across_calls() -> None:
    tenant = TenantIdentity(tenant_id="t1")
    s1 = establish_tenant_session(tenant)
    s2 = establish_tenant_session(tenant)
    assert s1.session_id != s2.session_id


def test_consume_sequence_increments() -> None:
    s = establish_tenant_session(TenantIdentity(tenant_id="t1"))
    assert s.consume_sequence() == 1
    assert s.consume_sequence() == 2
    assert s.consume_sequence() == 3
    assert s.entries_encrypted == 3


def test_rotate_key_resets_counters() -> None:
    s = establish_tenant_session(TenantIdentity(tenant_id="t1"))
    s.consume_sequence()
    s.consume_sequence()
    assert s.entries_encrypted == 2
    new_key = b"\x11" * 32
    s.rotate_key(new_key)
    assert s.symmetric_key == new_key
    assert s.entries_encrypted == 0
    assert s.next_sequence == 1


def test_is_valid_true_initially() -> None:
    s = establish_tenant_session(TenantIdentity(tenant_id="t1"))
    assert s.is_valid()


def test_expired_session_check_valid_raises() -> None:
    s = establish_tenant_session(TenantIdentity(tenant_id="t1"))
    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    s.expires_at = past.isoformat()
    assert not s.is_valid()
    with pytest.raises(SessionExpiredError):
        s.check_valid()
