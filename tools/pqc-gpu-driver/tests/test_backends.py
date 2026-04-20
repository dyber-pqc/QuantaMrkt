"""Tests for the GPU backends."""

from __future__ import annotations

import pytest

from pqc_gpu_driver import (
    BackendError,
    CUDABackend,
    InMemoryBackend,
    ROCmBackend,
    TensorMetadata,
    establish_channel,
)


def _fake_tensor(random_tensor_bytes: bytes):
    cpu, _gpu = establish_channel()
    meta = TensorMetadata(
        tensor_id="t-backend",
        name="some.weights",
        dtype="float32",
        shape=(len(random_tensor_bytes) // 4,),
        size_bytes=len(random_tensor_bytes),
    )
    return cpu.encrypt_tensor(random_tensor_bytes, meta)


def test_in_memory_backend_upload_download_roundtrip(
    random_tensor_bytes: bytes,
) -> None:
    be = InMemoryBackend()
    enc = _fake_tensor(random_tensor_bytes)
    handle = be.upload(enc)
    assert handle.startswith("mem:")
    pulled = be.download(handle)
    assert pulled.ciphertext == enc.ciphertext
    assert pulled.nonce == enc.nonce
    assert pulled.sequence_number == enc.sequence_number
    info = be.device_info()
    assert info["device_type"] == "in-memory"
    assert info["live_handles"] == 1


def test_in_memory_backend_free_removes_handle(
    random_tensor_bytes: bytes,
) -> None:
    be = InMemoryBackend()
    handle = be.upload(_fake_tensor(random_tensor_bytes))
    be.free(handle)
    with pytest.raises(BackendError):
        be.download(handle)
    with pytest.raises(BackendError):
        be.free(handle)


def test_cuda_backend_raises_backend_error(random_tensor_bytes: bytes) -> None:
    be = CUDABackend(device_index=0)
    enc = _fake_tensor(random_tensor_bytes)
    with pytest.raises(BackendError):
        be.upload(enc)
    with pytest.raises(BackendError):
        be.download("cuda:fake")
    with pytest.raises(BackendError):
        be.free("cuda:fake")
    with pytest.raises(BackendError):
        be.device_info()


def test_rocm_backend_raises_backend_error(random_tensor_bytes: bytes) -> None:
    be = ROCmBackend(device_index=0)
    enc = _fake_tensor(random_tensor_bytes)
    with pytest.raises(BackendError):
        be.upload(enc)
    with pytest.raises(BackendError):
        be.download("hip:fake")
    with pytest.raises(BackendError):
        be.free("hip:fake")
    with pytest.raises(BackendError):
        be.device_info()
