"""Tests for KV cache entry data structures."""

from __future__ import annotations

import pytest

from pqc_kv_cache.entry import EncryptedEntry, EntryMetadata, KVCacheEntry


def test_entry_metadata_roundtrip() -> None:
    meta = EntryMetadata(
        tenant_id="t1",
        session_id="s1",
        layer_idx=3,
        position=7,
        token_id=42,
        kv_role="both",
    )
    d = meta.to_dict()
    assert d["tenant_id"] == "t1"
    assert d["layer_idx"] == 3
    assert d["position"] == 7
    assert d["token_id"] == 42
    assert d["kv_role"] == "both"


def test_encrypted_entry_roundtrip() -> None:
    meta = EntryMetadata(
        tenant_id="t1", session_id="s1", layer_idx=0, position=0
    )
    enc = EncryptedEntry(
        metadata=meta,
        nonce="aa" * 12,
        ciphertext="bb" * 64,
        key_len=32,
        sequence_number=9,
    )
    data = enc.to_dict()
    restored = EncryptedEntry.from_dict(data)
    assert restored.metadata == meta
    assert restored.nonce == enc.nonce
    assert restored.ciphertext == enc.ciphertext
    assert restored.key_len == 32
    assert restored.sequence_number == 9


def test_kvcache_entry_plaintext_size() -> None:
    meta = EntryMetadata(tenant_id="t", session_id="s", layer_idx=0, position=0)
    entry = KVCacheEntry(
        metadata=meta,
        key_tensor_bytes=b"\x00" * 64,
        value_tensor_bytes=b"\x00" * 96,
    )
    assert entry.plaintext_size() == 160


def test_entry_metadata_frozen() -> None:
    meta = EntryMetadata(tenant_id="t", session_id="s", layer_idx=0, position=0)
    with pytest.raises(Exception):
        meta.tenant_id = "other"  # type: ignore[misc]
