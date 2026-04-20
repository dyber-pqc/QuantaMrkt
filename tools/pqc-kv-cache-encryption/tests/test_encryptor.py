"""Tests for CacheEncryptor / CacheDecryptor."""

from __future__ import annotations

import dataclasses

import pytest

from pqc_kv_cache.encryptor import CacheDecryptor, CacheEncryptor
from pqc_kv_cache.entry import EncryptedEntry, EntryMetadata, KVCacheEntry
from pqc_kv_cache.errors import (
    DecryptionError,
    NonceReplayError,
    TenantIsolationError,
)


def test_encrypt_returns_encrypted_entry(
    session_alice, sample_entry_factory
) -> None:
    entry = sample_entry_factory(session_alice, 0, 0)
    enc = CacheEncryptor(session_alice).encrypt_entry(entry)
    assert isinstance(enc, EncryptedEntry)
    assert len(bytes.fromhex(enc.nonce)) == 12
    assert len(bytes.fromhex(enc.ciphertext)) > 0
    assert enc.sequence_number == 1


def test_encrypt_then_decrypt_roundtrip(
    session_alice, sample_entry_factory
) -> None:
    entry = sample_entry_factory(session_alice, 2, 5)
    enc = CacheEncryptor(session_alice).encrypt_entry(entry)
    dec = CacheDecryptor(session_alice).decrypt_entry(enc)
    assert dec.metadata == entry.metadata
    assert dec.key_tensor_bytes == entry.key_tensor_bytes
    assert dec.value_tensor_bytes == entry.value_tensor_bytes


def test_tenant_id_mismatch_on_encrypt_raises(
    session_alice, tenant_bob
) -> None:
    foreign_meta = EntryMetadata(
        tenant_id=tenant_bob.tenant_id,
        session_id=session_alice.session_id,
        layer_idx=0,
        position=0,
    )
    entry = KVCacheEntry(
        metadata=foreign_meta,
        key_tensor_bytes=b"\x00" * 32,
        value_tensor_bytes=b"\x00" * 32,
    )
    with pytest.raises(TenantIsolationError):
        CacheEncryptor(session_alice).encrypt_entry(entry)


def test_wrong_tenant_session_decrypt_raises(
    session_alice, session_bob, sample_entry_factory
) -> None:
    entry = sample_entry_factory(session_alice, 0, 0)
    enc = CacheEncryptor(session_alice).encrypt_entry(entry)
    with pytest.raises(TenantIsolationError):
        CacheDecryptor(session_bob).decrypt_entry(enc)


def test_sequence_counter_increments(
    session_alice, sample_entry_factory
) -> None:
    enc1 = CacheEncryptor(session_alice).encrypt_entry(
        sample_entry_factory(session_alice, 0, 0)
    )
    enc2 = CacheEncryptor(session_alice).encrypt_entry(
        sample_entry_factory(session_alice, 0, 1)
    )
    enc3 = CacheEncryptor(session_alice).encrypt_entry(
        sample_entry_factory(session_alice, 0, 2)
    )
    assert (enc1.sequence_number, enc2.sequence_number, enc3.sequence_number) == (1, 2, 3)


def test_aad_tamper_detected(session_alice, sample_entry_factory) -> None:
    entry = sample_entry_factory(session_alice, 0, 0)
    enc = CacheEncryptor(session_alice).encrypt_entry(entry)
    tampered_meta = dataclasses.replace(enc.metadata, layer_idx=99)
    tampered = EncryptedEntry(
        metadata=tampered_meta,
        nonce=enc.nonce,
        ciphertext=enc.ciphertext,
        key_len=enc.key_len,
        sequence_number=enc.sequence_number,
    )
    with pytest.raises(DecryptionError):
        CacheDecryptor(session_alice).decrypt_entry(tampered)


def test_ciphertext_tamper_detected(
    session_alice, sample_entry_factory
) -> None:
    entry = sample_entry_factory(session_alice, 0, 0)
    enc = CacheEncryptor(session_alice).encrypt_entry(entry)
    flipped = bytearray(bytes.fromhex(enc.ciphertext))
    flipped[0] ^= 0x01
    tampered = EncryptedEntry(
        metadata=enc.metadata,
        nonce=enc.nonce,
        ciphertext=flipped.hex(),
        key_len=enc.key_len,
        sequence_number=enc.sequence_number,
    )
    with pytest.raises(DecryptionError):
        CacheDecryptor(session_alice).decrypt_entry(tampered)


def test_replay_detected(session_alice, sample_entry_factory) -> None:
    entry = sample_entry_factory(session_alice, 0, 0)
    enc = CacheEncryptor(session_alice).encrypt_entry(entry)
    dec = CacheDecryptor(session_alice)
    dec.decrypt_entry(enc)
    with pytest.raises(NonceReplayError):
        dec.decrypt_entry(enc)
