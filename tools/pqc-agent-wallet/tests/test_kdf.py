"""Tests for PBKDF2 key derivation."""

from __future__ import annotations

from pqc_agent_wallet.kdf import derive_key_from_passphrase


def test_same_inputs_produce_same_key() -> None:
    salt = b"\x01" * 16
    k1 = derive_key_from_passphrase("hunter2", salt, iterations=1000)
    k2 = derive_key_from_passphrase("hunter2", salt, iterations=1000)
    assert k1 == k2


def test_different_salt_produces_different_key() -> None:
    k1 = derive_key_from_passphrase("hunter2", b"\x01" * 16, iterations=1000)
    k2 = derive_key_from_passphrase("hunter2", b"\x02" * 16, iterations=1000)
    assert k1 != k2


def test_different_passphrase_produces_different_key() -> None:
    salt = b"\x01" * 16
    k1 = derive_key_from_passphrase("hunter2", salt, iterations=1000)
    k2 = derive_key_from_passphrase("hunter3", salt, iterations=1000)
    assert k1 != k2


def test_default_length_is_32_bytes() -> None:
    k = derive_key_from_passphrase("hunter2", b"\x01" * 16, iterations=1000)
    assert len(k) == 32
