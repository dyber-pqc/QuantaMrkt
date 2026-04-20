"""Tests for EnclaveAuditLog."""

from __future__ import annotations

from pqc_enclave_sdk import EnclaveAuditLog


def test_log_unlock_appends() -> None:
    log = EnclaveAuditLog()
    log.log_unlock(device_id="d-1", key_id="urn:pqc-enclave-key:abc")
    assert len(log) == 1
    entries = log.entries()
    assert entries[0].operation == "unlock"
    assert entries[0].device_id == "d-1"
    assert "abc" in entries[0].details


def test_log_put_captures_artifact_id_and_kind() -> None:
    log = EnclaveAuditLog()
    log.log_put(
        device_id="d-1",
        artifact_id="urn:pqc-enclave-art:1",
        artifact_name="llama",
        artifact_kind="model-weights",
    )
    e = log.entries()[0]
    assert e.artifact_id == "urn:pqc-enclave-art:1"
    assert e.artifact_name == "llama"
    assert e.artifact_kind == "model-weights"


def test_filter_by_operation() -> None:
    log = EnclaveAuditLog()
    log.log_unlock("d", "k-1")
    log.log_put("d", "id-1", "n", "credential")
    log.log_get("d", "id-1")
    log.log_lock("d")
    puts = log.entries(operation="put")
    assert len(puts) == 1
    assert puts[0].operation == "put"


def test_filter_by_device_id() -> None:
    log = EnclaveAuditLog()
    log.log_unlock("d-alice", "k-1")
    log.log_unlock("d-bob", "k-2")
    alice = log.entries(device_id="d-alice")
    bob = log.entries(device_id="d-bob")
    assert len(alice) == 1
    assert len(bob) == 1
    assert alice[0].device_id == "d-alice"
    assert bob[0].device_id == "d-bob"
