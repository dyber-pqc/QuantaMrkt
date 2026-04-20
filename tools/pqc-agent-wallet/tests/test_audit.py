"""Tests for the wallet audit log."""

from __future__ import annotations

import pytest
from quantumshield.core.keys import get_backend

from pqc_agent_wallet import Wallet
from pqc_agent_wallet.errors import CredentialNotFoundError


def test_put_records_audit_entry(open_wallet: Wallet) -> None:
    entries = open_wallet.audit.entries(operation="put")
    names = [e.credential_name for e in entries]
    assert "openai_api_key" in names
    assert "postgres_password" in names
    assert all(e.success for e in entries)


def test_get_records_audit_entry(open_wallet: Wallet) -> None:
    open_wallet.get("openai_api_key")
    get_entries = open_wallet.audit.entries(operation="get")
    assert any(
        e.credential_name == "openai_api_key" and e.success for e in get_entries
    )


def test_failed_get_records_failure(open_wallet: Wallet) -> None:
    with pytest.raises(CredentialNotFoundError):
        open_wallet.get("nonexistent")
    failures = [e for e in open_wallet.audit.entries(operation="get") if not e.success]
    assert any(e.credential_name == "nonexistent" for e in failures)


def test_audit_entries_signed_and_verifiable(open_wallet: Wallet) -> None:
    if get_backend() == "stub":
        pytest.skip("requires real signature backend")

    pk_hex = open_wallet.owner.signing_keypair.public_key.hex()
    entries = open_wallet.audit.entries(limit=100)
    assert entries, "expected at least one audit entry"
    for entry in entries:
        assert entry.signature
        assert entry.algorithm
        assert entry.verify_signature(pk_hex) is True


def test_audit_filter_by_operation(open_wallet: Wallet) -> None:
    open_wallet.get("openai_api_key")
    puts = open_wallet.audit.entries(operation="put")
    gets = open_wallet.audit.entries(operation="get")
    assert all(e.operation == "put" for e in puts)
    assert all(e.operation == "get" for e in gets)


def test_audit_filter_by_credential_name(open_wallet: Wallet) -> None:
    open_wallet.get("postgres_password")
    filtered = open_wallet.audit.entries(credential_name="postgres_password")
    assert filtered
    assert all(e.credential_name == "postgres_password" for e in filtered)


def test_audit_export_json_roundtrip(open_wallet: Wallet) -> None:
    data = open_wallet.audit.export_json()
    assert "timestamp" in data
    assert "put" in data


def test_audit_log_len(open_wallet: Wallet) -> None:
    # open_wallet fixture: 2 puts produce 2 entries
    assert len(open_wallet.audit) >= 2
