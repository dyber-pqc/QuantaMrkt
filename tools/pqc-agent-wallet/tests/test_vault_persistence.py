"""Tests for Wallet persistence: save, load, tamper detection."""

from __future__ import annotations

import json

import pytest
from quantumshield.core.keys import get_backend

from pqc_agent_wallet import Wallet
from pqc_agent_wallet.errors import (
    InvalidPassphraseError,
    TamperedWalletError,
    WalletFormatError,
)


def test_save_and_load_roundtrip(open_wallet: Wallet, owner, wallet_path) -> None:
    open_wallet.save()
    open_wallet.lock()

    reloaded = Wallet.load(wallet_path, owner)
    reloaded.unlock_with_passphrase("correct-horse-battery")
    assert reloaded.get("openai_api_key") == "sk-test-openai"
    assert reloaded.get("postgres_password") == "db-pass-123"
    assert sorted(reloaded.list_names()) == ["openai_api_key", "postgres_password"]


def test_tampered_wallet_file_rejected(open_wallet: Wallet, owner, wallet_path) -> None:
    """Flip a byte in an encrypted credential and verify load() detects it.

    Requires a real signature backend. If the stub backend is active, skip.
    """
    if get_backend() == "stub":
        pytest.skip("requires real signature backend to detect tampering")

    open_wallet.save()
    with open(wallet_path, encoding="utf-8") as f:
        envelope = json.load(f)

    # Flip a byte in one of the encrypted credential nonces (still valid hex)
    any_name = next(iter(envelope["encrypted_credentials"]))
    nonce_hex = envelope["encrypted_credentials"][any_name]["nonce"]
    first_char = nonce_hex[0]
    replaced = "0" if first_char != "0" else "1"
    envelope["encrypted_credentials"][any_name]["nonce"] = replaced + nonce_hex[1:]

    with open(wallet_path, "w", encoding="utf-8") as f:
        json.dump(envelope, f, indent=2)

    with pytest.raises(TamperedWalletError):
        Wallet.load(wallet_path, owner)


def test_wrong_passphrase_raises(open_wallet: Wallet, owner, wallet_path) -> None:
    open_wallet.save()
    reloaded = Wallet.load(wallet_path, owner)
    with pytest.raises(InvalidPassphraseError):
        reloaded.unlock_with_passphrase("wrong-phrase")


def test_fresh_wallet_unlock_accepts_any_passphrase(owner, tmp_path) -> None:
    """Behavior note: on a fresh wallet with no credentials, unlock cannot
    validate the passphrase because there's no ciphertext to decrypt against.
    unlock_with_passphrase therefore accepts any passphrase. Once credentials
    are added and the wallet is saved/reloaded, validation works normally.
    """
    path = str(tmp_path / "fresh.wallet")
    w = Wallet.create_with_passphrase(path, "original-phrase", owner)
    w.save()

    reloaded = Wallet.load(path, owner)
    # No credentials means no check happens - this is accepted.
    reloaded.unlock_with_passphrase("any-other-phrase")
    assert reloaded.is_unlocked


def test_wrong_format_version_raises(open_wallet: Wallet, owner, wallet_path) -> None:
    open_wallet.save()
    with open(wallet_path, encoding="utf-8") as f:
        envelope = json.load(f)
    envelope["version"] = "99.0"
    with open(wallet_path, "w", encoding="utf-8") as f:
        json.dump(envelope, f, indent=2)

    with pytest.raises(WalletFormatError):
        Wallet.load(wallet_path, owner)


def test_missing_signature_fields_raises(open_wallet: Wallet, owner, wallet_path) -> None:
    open_wallet.save()
    with open(wallet_path, encoding="utf-8") as f:
        envelope = json.load(f)
    envelope.pop("signature", None)
    with open(wallet_path, "w", encoding="utf-8") as f:
        json.dump(envelope, f, indent=2)

    with pytest.raises(WalletFormatError):
        Wallet.load(wallet_path, owner)
