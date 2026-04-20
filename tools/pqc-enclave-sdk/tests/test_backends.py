"""Tests for backends."""

from __future__ import annotations

import pytest

from pqc_enclave_sdk import (
    AndroidEnclaveBackend,
    ArtifactKind,
    ArtifactMetadata,
    BackendError,
    EncryptedArtifact,
    InMemoryEnclaveBackend,
    iOSEnclaveBackend,
)


def test_inmemory_backend_save_load_roundtrip() -> None:
    b = InMemoryEnclaveBackend(device_id="d")
    meta = ArtifactMetadata(
        artifact_id="urn:pqc-enclave-art:1",
        name="x",
        kind=ArtifactKind.CREDENTIAL,
    )
    enc = EncryptedArtifact(
        metadata=meta,
        nonce="00" * 12,
        ciphertext="ff",
        content_hash="ab",
        key_id="k",
    )
    b.save_artifacts({meta.artifact_id: enc})
    loaded = b.load_artifacts()
    assert meta.artifact_id in loaded
    assert loaded[meta.artifact_id].ciphertext == "ff"


def test_ios_backend_save_artifacts_raises_backend_error() -> None:
    b = iOSEnclaveBackend()
    with pytest.raises(BackendError):
        b.save_artifacts({})


def test_android_backend_store_session_key_raises_backend_error() -> None:
    b = AndroidEnclaveBackend()
    with pytest.raises(BackendError):
        b.store_session_key("urn:pqc-enclave-key:x", b"\x00" * 32, "")
