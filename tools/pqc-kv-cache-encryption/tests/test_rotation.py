"""Tests for KeyRotationPolicy."""

from __future__ import annotations

import time

from pqc_kv_cache.rotation import KeyRotationPolicy, RotationTrigger
from pqc_kv_cache.session import TenantIdentity, establish_tenant_session


def test_policy_no_trigger_below_thresholds() -> None:
    s = establish_tenant_session(TenantIdentity(tenant_id="t1"))
    policy = KeyRotationPolicy(max_entries=1000, max_age_seconds=3600)
    should, trigger = policy.should_rotate(s)
    assert should is False
    assert trigger is None


def test_policy_triggers_on_entry_count() -> None:
    s = establish_tenant_session(TenantIdentity(tenant_id="t1"))
    policy = KeyRotationPolicy(max_entries=3, max_age_seconds=3600)
    for _ in range(3):
        s.consume_sequence()
    should, trigger = policy.should_rotate(s)
    assert should is True
    assert trigger is RotationTrigger.ENTRY_COUNT


def test_policy_triggers_on_time_elapsed() -> None:
    s = establish_tenant_session(TenantIdentity(tenant_id="t1"))
    policy = KeyRotationPolicy(max_entries=1000, max_age_seconds=1)
    time.sleep(1.1)
    should, trigger = policy.should_rotate(s)
    assert should is True
    assert trigger is RotationTrigger.TIME_ELAPSED


def test_rotate_produces_new_32_byte_key() -> None:
    s = establish_tenant_session(TenantIdentity(tenant_id="t1"))
    policy = KeyRotationPolicy()
    old_key = s.symmetric_key
    new_key = policy.rotate(s)
    assert len(new_key) == 32
    assert new_key != old_key
    assert s.symmetric_key == new_key


def test_rotate_resets_entries_encrypted() -> None:
    s = establish_tenant_session(TenantIdentity(tenant_id="t1"))
    for _ in range(5):
        s.consume_sequence()
    assert s.entries_encrypted == 5
    KeyRotationPolicy().rotate(s)
    assert s.entries_encrypted == 0
    assert s.next_sequence == 1
