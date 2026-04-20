"""Tests for EnclaveVault lifecycle and CRUD."""

from __future__ import annotations

import pytest

from pqc_enclave_sdk import (
    ArtifactKind,
    EnclaveLockedError,
    EnclaveVault,
    InMemoryEnclaveBackend,
)


def test_unlock_sets_is_unlocked(backend: InMemoryEnclaveBackend) -> None:
    v = EnclaveVault(backend=backend)
    assert not v.is_unlocked
    v.unlock()
    assert v.is_unlocked


def test_lock_clears_key(vault: EnclaveVault) -> None:
    assert vault.is_unlocked
    vault.lock()
    assert not vault.is_unlocked


def test_put_requires_unlock(backend: InMemoryEnclaveBackend) -> None:
    v = EnclaveVault(backend=backend)
    with pytest.raises(EnclaveLockedError):
        v.put_artifact(
            name="foo", kind=ArtifactKind.CREDENTIAL, content=b"secret"
        )


def test_get_requires_unlock(
    vault: EnclaveVault, api_credential: bytes
) -> None:
    vault.put_artifact(
        name="openai", kind=ArtifactKind.CREDENTIAL, content=api_credential
    )
    vault.lock()
    with pytest.raises(EnclaveLockedError):
        vault.get_artifact("openai")


def test_put_get_roundtrip_preserves_content(
    vault: EnclaveVault, small_weights: bytes
) -> None:
    vault.put_artifact(
        name="tiny-weights",
        kind=ArtifactKind.MODEL_WEIGHTS,
        content=small_weights,
    )
    got = vault.get_artifact("tiny-weights")
    assert got.content == small_weights
    assert got.metadata.kind == ArtifactKind.MODEL_WEIGHTS


def test_put_by_kind_tagged_correctly(vault: EnclaveVault) -> None:
    enc = vault.put_artifact(
        name="lora-x",
        kind=ArtifactKind.LORA_ADAPTER,
        content=b"adapter-bytes",
    )
    assert enc.metadata.kind == ArtifactKind.LORA_ADAPTER
    assert enc.metadata.name == "lora-x"
    assert enc.metadata.size_bytes == len(b"adapter-bytes")


def test_get_by_name_works(
    vault: EnclaveVault, api_credential: bytes
) -> None:
    enc = vault.put_artifact(
        name="stripe-key",
        kind=ArtifactKind.CREDENTIAL,
        content=api_credential,
    )
    got_by_name = vault.get_artifact("stripe-key")
    got_by_id = vault.get_artifact(enc.metadata.artifact_id)
    assert got_by_name.content == api_credential
    assert got_by_id.content == api_credential


def test_delete_removes_both_id_and_name_entries(
    vault: EnclaveVault,
) -> None:
    enc = vault.put_artifact(
        name="temp", kind=ArtifactKind.OTHER, content=b"temp-bytes"
    )
    aid = enc.metadata.artifact_id
    vault.delete_artifact("temp")
    # Neither name nor id should resolve now.
    from pqc_enclave_sdk import UnknownArtifactError

    with pytest.raises(UnknownArtifactError):
        vault.get_artifact("temp")
    with pytest.raises(UnknownArtifactError):
        vault.get_artifact(aid)


def test_list_artifacts_returns_unique_metadata(vault: EnclaveVault) -> None:
    vault.put_artifact(name="a", kind=ArtifactKind.CREDENTIAL, content=b"1")
    vault.put_artifact(name="b", kind=ArtifactKind.CREDENTIAL, content=b"2")
    vault.put_artifact(name="c", kind=ArtifactKind.TOKENIZER, content=b"3")
    metas = vault.list_artifacts()
    names = {m.name for m in metas}
    assert names == {"a", "b", "c"}
    # Ensure no duplicates even though the internal store double-indexes.
    ids = [m.artifact_id for m in metas]
    assert len(ids) == len(set(ids))


def test_save_and_reload_via_backend_preserves_artifacts(
    backend: InMemoryEnclaveBackend, small_weights: bytes
) -> None:
    v1 = EnclaveVault(backend=backend)
    v1.unlock()
    v1.put_artifact(
        name="weights-1",
        kind=ArtifactKind.MODEL_WEIGHTS,
        content=small_weights,
    )
    v1.save()

    # Fresh vault over the same backend - should load the persisted artifacts.
    v2 = EnclaveVault(backend=backend)
    # A brand new unlock yields a new session key - content decryption
    # therefore requires the original key. Demonstrate the save/load
    # pipeline shuttles EncryptedArtifact objects intact.
    loaded = backend.load_artifacts()
    assert any(
        enc.metadata.name == "weights-1" for enc in loaded.values()
    )
    # And v2.unlock() populates its own store from the backend.
    v2.unlock()
    names_in_store = {
        enc.metadata.name for enc in v2._store.values()
    }
    assert "weights-1" in names_in_store
