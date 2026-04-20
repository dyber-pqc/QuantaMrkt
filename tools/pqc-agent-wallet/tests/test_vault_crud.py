"""Tests for Wallet CRUD operations."""

from __future__ import annotations

import pytest

from pqc_agent_wallet import Wallet
from pqc_agent_wallet.errors import CredentialNotFoundError, WalletLockedError


def test_put_and_get_roundtrip(open_wallet: Wallet) -> None:
    assert open_wallet.get("openai_api_key") == "sk-test-openai"
    assert open_wallet.get("postgres_password") == "db-pass-123"


def test_get_missing_raises(open_wallet: Wallet) -> None:
    with pytest.raises(CredentialNotFoundError):
        open_wallet.get("does-not-exist")


def test_put_requires_unlock(open_wallet: Wallet) -> None:
    open_wallet.lock()
    with pytest.raises(WalletLockedError):
        open_wallet.put("x", "y")


def test_get_requires_unlock(open_wallet: Wallet) -> None:
    open_wallet.lock()
    with pytest.raises(WalletLockedError):
        open_wallet.get("openai_api_key")


def test_delete_requires_unlock(open_wallet: Wallet) -> None:
    open_wallet.lock()
    with pytest.raises(WalletLockedError):
        open_wallet.delete("openai_api_key")


def test_delete_removes_credential(open_wallet: Wallet) -> None:
    open_wallet.delete("openai_api_key")
    assert "openai_api_key" not in open_wallet.list_names()
    with pytest.raises(CredentialNotFoundError):
        open_wallet.get("openai_api_key")


def test_delete_missing_raises(open_wallet: Wallet) -> None:
    with pytest.raises(CredentialNotFoundError):
        open_wallet.delete("does-not-exist")


def test_list_names_sorted(open_wallet: Wallet) -> None:
    names = open_wallet.list_names()
    assert names == sorted(names)
    assert "openai_api_key" in names
    assert "postgres_password" in names


def test_rotate_updates_rotated_at_and_preserves_created_at(
    open_wallet: Wallet,
) -> None:
    original_created = next(
        m.created_at
        for m in open_wallet.list_metadata()
        if m.name == "openai_api_key"
    )
    assert original_created != ""

    open_wallet.rotate("openai_api_key", "sk-rotated-value")

    rotated_meta = next(
        m for m in open_wallet.list_metadata() if m.name == "openai_api_key"
    )
    assert rotated_meta.created_at == original_created
    assert rotated_meta.rotated_at != ""
    assert open_wallet.get("openai_api_key") == "sk-rotated-value"


def test_get_credential_returns_metadata_and_value(open_wallet: Wallet) -> None:
    cred = open_wallet.get_credential("openai_api_key")
    assert cred.value == "sk-test-openai"
    assert cred.metadata.name == "openai_api_key"
    assert cred.metadata.service == "openai"
