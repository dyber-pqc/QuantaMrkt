"""Tests for UpdateChain."""

from __future__ import annotations

import pytest

from pqc_bootloader.errors import FirmwareRollbackError, UpdateChainError
from pqc_bootloader.firmware import FirmwareImage, FirmwareMetadata, TargetDevice
from pqc_bootloader.signer import FirmwareSigner
from pqc_bootloader.update_chain import UpdateChain


def _fw(version: str, payload: bytes, name: str = "acme-inference-os") -> FirmwareImage:
    meta = FirmwareMetadata(
        name=name,
        version=version,
        target=TargetDevice.AI_INFERENCE_APPLIANCE,
    )
    return FirmwareImage.from_bytes(meta, payload)


def test_add_first_link_ok(firmware_signer: FirmwareSigner) -> None:
    chain = UpdateChain()
    fw = _fw("1.0.0", b"v1 payload")
    signed = firmware_signer.sign(fw)
    chain.add(signed)
    assert chain.current() is signed
    ok, errors = chain.verify_chain()
    assert ok and errors == []


def test_second_link_verifies_previous_hash(firmware_signer: FirmwareSigner) -> None:
    chain = UpdateChain()
    v1 = firmware_signer.sign(_fw("1.0.0", b"v1 payload"))
    v2 = firmware_signer.sign(
        _fw("1.1.0", b"v2 payload"),
        previous_firmware_hash=v1.firmware.image_hash,
    )
    chain.add(v1)
    chain.add(v2)
    ok, errors = chain.verify_chain()
    assert ok and errors == []


def test_mismatched_previous_hash_raises(firmware_signer: FirmwareSigner) -> None:
    chain = UpdateChain()
    v1 = firmware_signer.sign(_fw("1.0.0", b"v1 payload"))
    v2 = firmware_signer.sign(
        _fw("1.1.0", b"v2 payload"),
        previous_firmware_hash="de" * 32,  # wrong
    )
    chain.add(v1)
    with pytest.raises(UpdateChainError):
        chain.add(v2)


def test_rollback_blocked_by_default(firmware_signer: FirmwareSigner) -> None:
    chain = UpdateChain()
    v1 = firmware_signer.sign(_fw("1.0.0", b"v1 payload"))
    v0 = firmware_signer.sign(
        _fw("0.9.0", b"v0 payload"),
        previous_firmware_hash=v1.firmware.image_hash,
    )
    chain.add(v1)
    with pytest.raises(FirmwareRollbackError):
        chain.add(v0)


def test_rollback_allowed_when_flag_set(firmware_signer: FirmwareSigner) -> None:
    chain = UpdateChain()
    v1 = firmware_signer.sign(_fw("1.0.0", b"v1 payload"))
    v0 = firmware_signer.sign(
        _fw("0.9.0", b"v0 payload"),
        previous_firmware_hash=v1.firmware.image_hash,
    )
    chain.add(v1)
    chain.add(v0, allow_rollback=True)
    assert chain.current() is v0
