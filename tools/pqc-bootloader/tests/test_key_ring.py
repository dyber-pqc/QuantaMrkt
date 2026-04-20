"""Tests for KeyRing."""

from __future__ import annotations

import pytest

from pqc_bootloader.errors import UnknownKeyError
from pqc_bootloader.key_ring import KeyRing


def _fake_pk_hex(byte: int = 0xAB) -> str:
    return (bytes([byte]) * 32).hex()


def test_add_assigns_fingerprint() -> None:
    ring = KeyRing()
    entry = ring.add(_fake_pk_hex(0x11), "ML-DSA-65", "Acme Inc.")
    assert entry.key_id == KeyRing.fingerprint(_fake_pk_hex(0x11))
    assert entry.manufacturer == "Acme Inc."
    assert entry.revoked is False


def test_fingerprint_deterministic_and_is_trusted_true_after_add() -> None:
    pk = _fake_pk_hex(0x22)
    assert KeyRing.fingerprint(pk) == KeyRing.fingerprint(pk)

    ring = KeyRing()
    entry = ring.add(pk, "ML-DSA-65", "Acme Inc.")
    assert ring.is_trusted(entry.key_id) is True
    assert len(ring) == 1


def test_revoke_marks_entry_and_is_trusted_false() -> None:
    ring = KeyRing()
    entry = ring.add(_fake_pk_hex(0x33), "ML-DSA-65", "Acme Inc.")
    ring.revoke(entry.key_id, reason="key compromised in 2030 breach")
    fetched = ring.get(entry.key_id)
    assert fetched.revoked is True
    assert "compromised" in fetched.revocation_reason
    assert ring.is_trusted(entry.key_id) is False


def test_get_missing_raises_unknown_key_error() -> None:
    ring = KeyRing()
    with pytest.raises(UnknownKeyError):
        ring.get("nonexistent-key-id")


def test_revoke_missing_raises_unknown_key_error() -> None:
    ring = KeyRing()
    with pytest.raises(UnknownKeyError):
        ring.revoke("nonexistent-key-id", reason="n/a")
