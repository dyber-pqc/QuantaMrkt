"""Tests for the EncryptedTensor / TensorMetadata envelope."""

from __future__ import annotations

from pqc_gpu_driver import EncryptedTensor, TensorMetadata


def test_tensor_metadata_roundtrip() -> None:
    meta = TensorMetadata(
        tensor_id="t-1",
        name="model.dense_1.weights",
        dtype="float16",
        shape=(768, 3072),
        size_bytes=768 * 3072 * 2,
        transfer_direction="cpu_to_gpu",
    )
    decoded = TensorMetadata.from_dict(meta.to_dict())
    assert decoded == meta


def test_encrypted_tensor_roundtrip() -> None:
    meta = TensorMetadata(tensor_id="t-2", shape=(4, 4), size_bytes=64)
    enc = EncryptedTensor(
        metadata=meta,
        nonce="a" * 24,
        ciphertext="deadbeef" * 8,
        sequence_number=7,
    )
    decoded = EncryptedTensor.from_dict(enc.to_dict())
    assert decoded.metadata == meta
    assert decoded.nonce == enc.nonce
    assert decoded.ciphertext == enc.ciphertext
    assert decoded.sequence_number == 7


def test_tensor_metadata_preserves_shape_tuple() -> None:
    meta = TensorMetadata(tensor_id="t-3", shape=(1, 2, 3, 4))
    # to_dict downgrades shape to list (JSON-compatible)
    assert meta.to_dict()["shape"] == [1, 2, 3, 4]
    # from_dict restores to tuple
    restored = TensorMetadata.from_dict(meta.to_dict())
    assert isinstance(restored.shape, tuple)
    assert restored.shape == (1, 2, 3, 4)
