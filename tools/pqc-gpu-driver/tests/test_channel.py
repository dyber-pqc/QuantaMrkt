"""Tests for ChannelSession and establish_channel()."""

from __future__ import annotations

import time

import pytest

from pqc_gpu_driver import (
    ChannelExpiredError,
    DecryptionError,
    NonceReplayError,
    TensorMetadata,
    establish_channel,
)


def _meta(tid: str, size: int) -> TensorMetadata:
    return TensorMetadata(
        tensor_id=tid,
        name="model.layer_0.weights",
        dtype="float32",
        shape=(size // 4,),
        size_bytes=size,
        transfer_direction="cpu_to_gpu",
    )


def test_establish_channel_returns_matching_sessions() -> None:
    cpu, gpu = establish_channel()
    assert cpu.session_id == gpu.session_id
    assert cpu.symmetric_key == gpu.symmetric_key
    assert cpu.peer_label == "gpu"
    assert gpu.peer_label == "cpu"
    assert cpu.algorithm == "ML-KEM-768"
    assert cpu.is_valid()
    assert gpu.is_valid()


def test_encrypt_decrypt_roundtrip(random_tensor_bytes: bytes) -> None:
    cpu, gpu = establish_channel()
    meta = _meta("t-1", len(random_tensor_bytes))
    enc = cpu.encrypt_tensor(random_tensor_bytes, meta)
    pt = gpu.decrypt_tensor(enc)
    assert pt == random_tensor_bytes
    assert enc.sequence_number == 1
    assert cpu.next_send_seq == 2


def test_decrypt_with_wrong_nonce_fails(random_tensor_bytes: bytes) -> None:
    cpu, gpu = establish_channel()
    meta = _meta("t-1", len(random_tensor_bytes))
    enc = cpu.encrypt_tensor(random_tensor_bytes, meta)
    # Flip a byte of the nonce.
    flipped_nonce = ("0" if enc.nonce[0] != "0" else "1") + enc.nonce[1:]
    enc.nonce = flipped_nonce
    with pytest.raises(DecryptionError):
        gpu.decrypt_tensor(enc)


def test_aad_tamper_detected(random_tensor_bytes: bytes) -> None:
    cpu, gpu = establish_channel()
    meta = _meta("t-1", len(random_tensor_bytes))
    enc = cpu.encrypt_tensor(random_tensor_bytes, meta)

    # Swap metadata post-encrypt - AAD mismatch should surface as DecryptionError.
    enc.metadata = TensorMetadata(
        tensor_id="t-999",
        name="attacker.renamed",
        dtype=meta.dtype,
        shape=meta.shape,
        size_bytes=meta.size_bytes,
        transfer_direction=meta.transfer_direction,
    )
    with pytest.raises(DecryptionError):
        gpu.decrypt_tensor(enc)


def test_replay_rejected(random_tensor_bytes: bytes) -> None:
    cpu, gpu = establish_channel()
    meta = _meta("t-1", len(random_tensor_bytes))
    enc = cpu.encrypt_tensor(random_tensor_bytes, meta)
    assert gpu.decrypt_tensor(enc) == random_tensor_bytes
    # Replay same envelope.
    with pytest.raises(NonceReplayError):
        gpu.decrypt_tensor(enc)


def test_lower_sequence_rejected(random_tensor_bytes: bytes) -> None:
    cpu, gpu = establish_channel()
    meta = _meta("t-1", len(random_tensor_bytes))
    enc1 = cpu.encrypt_tensor(random_tensor_bytes, meta)
    enc2 = cpu.encrypt_tensor(random_tensor_bytes, meta)

    gpu.decrypt_tensor(enc2)
    with pytest.raises(NonceReplayError):
        gpu.decrypt_tensor(enc1)


def test_expired_session_raises(random_tensor_bytes: bytes) -> None:
    cpu, _gpu = establish_channel(ttl_seconds=0)
    # Ensure current time drifts past expires_at even with clock granularity.
    time.sleep(0.05)
    meta = _meta("t-1", len(random_tensor_bytes))
    with pytest.raises(ChannelExpiredError):
        cpu.encrypt_tensor(random_tensor_bytes, meta)


def test_sequence_numbers_increment(random_tensor_bytes: bytes) -> None:
    cpu, _gpu = establish_channel()
    meta = _meta("t-1", len(random_tensor_bytes))
    enc1 = cpu.encrypt_tensor(random_tensor_bytes, meta)
    enc2 = cpu.encrypt_tensor(random_tensor_bytes, meta)
    enc3 = cpu.encrypt_tensor(random_tensor_bytes, meta)
    assert [enc1.sequence_number, enc2.sequence_number, enc3.sequence_number] == [
        1,
        2,
        3,
    ]
    assert cpu.next_send_seq == 4
