"""Shared fixtures for the pqc-kv-cache-encryption test suite."""

from __future__ import annotations

import os
from collections.abc import Callable

import pytest

from pqc_kv_cache.entry import EntryMetadata, KVCacheEntry
from pqc_kv_cache.session import (
    TenantIdentity,
    TenantSession,
    establish_tenant_session,
)


@pytest.fixture
def tenant_alice() -> TenantIdentity:
    return TenantIdentity(tenant_id="tenant-alice", display_name="Alice Inc.")


@pytest.fixture
def tenant_bob() -> TenantIdentity:
    return TenantIdentity(tenant_id="tenant-bob", display_name="Bob LLC")


@pytest.fixture
def session_alice(tenant_alice: TenantIdentity) -> TenantSession:
    return establish_tenant_session(tenant_alice)


@pytest.fixture
def session_bob(tenant_bob: TenantIdentity) -> TenantSession:
    return establish_tenant_session(tenant_bob)


@pytest.fixture
def sample_k_bytes() -> bytes:
    return os.urandom(32)


@pytest.fixture
def sample_v_bytes() -> bytes:
    return os.urandom(32)


@pytest.fixture
def sample_entry_factory() -> Callable[[TenantSession, int, int], KVCacheEntry]:
    """Factory producing a fresh KVCacheEntry bound to a session/tenant."""

    def _make(session: TenantSession, layer: int, pos: int) -> KVCacheEntry:
        meta = EntryMetadata(
            tenant_id=session.tenant.tenant_id,
            session_id=session.session_id,
            layer_idx=layer,
            position=pos,
            token_id=1000 + pos,
            kv_role="both",
        )
        return KVCacheEntry(
            metadata=meta,
            key_tensor_bytes=os.urandom(32),
            value_tensor_bytes=os.urandom(32),
        )

    return _make
