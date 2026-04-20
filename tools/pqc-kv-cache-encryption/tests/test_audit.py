"""Tests for KVAuditLog."""

from __future__ import annotations

import json

from pqc_kv_cache.audit import KVAuditLog


def test_log_encrypt_appends() -> None:
    log = KVAuditLog()
    log.log_encrypt("tenant-a", "sess-a", layer_idx=0, position=0, seq=1)
    log.log_encrypt("tenant-a", "sess-a", layer_idx=0, position=1, seq=2)
    assert len(log) == 2


def test_filter_by_tenant() -> None:
    log = KVAuditLog()
    log.log_encrypt("tenant-a", "sess-a", 0, 0, 1)
    log.log_encrypt("tenant-b", "sess-b", 0, 0, 1)
    a_entries = log.entries(tenant_id="tenant-a")
    assert len(a_entries) == 1
    assert a_entries[0].tenant_id == "tenant-a"


def test_filter_by_operation() -> None:
    log = KVAuditLog()
    log.log_encrypt("tenant-a", "sess-a", 0, 0, 1)
    log.log_decrypt("tenant-a", "sess-a", 0, 0, 1, success=True)
    log.log_rotate("tenant-a", "sess-a", trigger="entry-count")
    log.log_isolation_violation("tenant-a", "tenant-b", details="cross-read")
    ops = {"encrypt", "decrypt", "rotate", "isolation-violation"}
    for op in ops:
        entries = log.entries(operation=op)
        assert len(entries) == 1
        assert entries[0].operation == op


def test_export_json_valid() -> None:
    log = KVAuditLog()
    log.log_encrypt("tenant-a", "sess-a", 0, 0, 1)
    log.log_rotate("tenant-a", "sess-a", trigger="manual")
    data = json.loads(log.export_json())
    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]["operation"] == "encrypt"
    assert data[1]["operation"] == "rotate"
