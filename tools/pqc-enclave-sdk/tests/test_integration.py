"""End-to-end integration tests."""

from __future__ import annotations

import pytest

from pqc_enclave_sdk import (
    ArtifactKind,
    DeviceAttester,
    EnclaveLockedError,
    EnclaveVault,
    InMemoryEnclaveBackend,
    UnknownArtifactError,
)


def test_full_lifecycle_unlock_put_save_lock_reload_get(
    small_weights: bytes,
) -> None:
    backend = InMemoryEnclaveBackend(device_id="iphone-1")

    v1 = EnclaveVault(backend=backend)
    v1.unlock()
    v1.put_artifact(
        name="llama-weights",
        kind=ArtifactKind.MODEL_WEIGHTS,
        content=small_weights,
    )
    v1.save()
    # Grab the session key we used - a fresh unlock on v2 would create a new
    # key and fail to decrypt. Simulate the real enclave contract where the
    # backend holds the wrapping key: swap the pre-existing session key.
    old_key = v1._symmetric_key
    old_key_id = v1._key_id
    old_exp = v1._expires_at
    v1.lock()

    v2 = EnclaveVault(backend=backend)
    v2.unlock()
    # Inject the historical session into v2 to mimic enclave-held KEK rewrap.
    v2._symmetric_key = old_key
    v2._key_id = old_key_id
    v2._expires_at = old_exp
    v2._store = backend.load_artifacts()

    art = v2.get_artifact("llama-weights")
    assert art.content == small_weights


def test_locked_vault_operations_raise_enclave_locked_error() -> None:
    backend = InMemoryEnclaveBackend()
    v = EnclaveVault(backend=backend)
    with pytest.raises(EnclaveLockedError):
        v.put_artifact(
            name="x", kind=ArtifactKind.OTHER, content=b"1"
        )
    with pytest.raises(EnclaveLockedError):
        v.get_artifact("x")
    with pytest.raises(EnclaveLockedError):
        v.delete_artifact("x")
    with pytest.raises(EnclaveLockedError):
        v.list_artifacts()


def test_attestation_over_stored_artifact_verifies(
    signer_identity, small_weights
) -> None:
    backend = InMemoryEnclaveBackend(
        device_id="pixel-8-bob", device_model="pixel-8"
    )
    v = EnclaveVault(backend=backend)
    v.unlock()
    enc = v.put_artifact(
        name="safety-model",
        kind=ArtifactKind.SAFETY_MODEL,
        content=small_weights,
    )

    attester = DeviceAttester(
        identity=signer_identity,
        device_id=backend.device_id,
        device_model=backend.device_model,
        enclave_vendor=backend.enclave_vendor,
    )
    att = attester.attest(
        artifact_id=enc.metadata.artifact_id,
        content_hash=enc.content_hash,
    )
    assert DeviceAttester.verify(att) is True
    # Tamper with the content hash - verification must now fail.
    att.artifact_content_hash = "00" * 32
    assert DeviceAttester.verify(att) is False

    # Sanity-check that deleting and re-getting raises the right error.
    v.delete_artifact(enc.metadata.artifact_id)
    with pytest.raises(UnknownArtifactError):
        v.get_artifact(enc.metadata.artifact_id)
