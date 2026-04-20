"""Tests for Wallet lock/unlock semantics."""

from __future__ import annotations

import pytest

from pqc_agent_wallet import Wallet
from pqc_agent_wallet.errors import WalletLockedError


def test_lock_clears_key(open_wallet: Wallet) -> None:
    assert open_wallet.is_unlocked
    open_wallet.lock()
    assert not open_wallet.is_unlocked


def test_operations_fail_after_lock(open_wallet: Wallet) -> None:
    open_wallet.lock()
    with pytest.raises(WalletLockedError):
        open_wallet.get("openai_api_key")
    with pytest.raises(WalletLockedError):
        open_wallet.put("foo", "bar")
    with pytest.raises(WalletLockedError):
        open_wallet.delete("openai_api_key")


def test_context_manager_locks_on_exit(open_wallet: Wallet) -> None:
    with open_wallet as w:
        assert w.is_unlocked
        assert w.get("openai_api_key") == "sk-test-openai"
    assert not open_wallet.is_unlocked
