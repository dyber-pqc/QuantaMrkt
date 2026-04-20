"""Tests for FirmwareSigner / FirmwareVerifier."""

from __future__ import annotations

import pytest

from pqc_bootloader.errors import FirmwareVerificationError
from pqc_bootloader.firmware import FirmwareImage
from pqc_bootloader.key_ring import KeyRing
from pqc_bootloader.signer import FirmwareSigner, FirmwareVerifier


def test_sign_populates_fields(
    firmware_signer: FirmwareSigner, sample_firmware: FirmwareImage
) -> None:
    signed = firmware_signer.sign(sample_firmware)
    assert signed.signature
    assert signed.public_key
    assert signed.signer_did.startswith("did:pqaid:")
    assert signed.algorithm
    assert signed.manufacturer_key_id == firmware_signer.key_id
    assert signed.firmware.image_hash == sample_firmware.image_hash


def test_verify_valid(
    firmware_signer: FirmwareSigner, sample_firmware: FirmwareImage
) -> None:
    signed = firmware_signer.sign(sample_firmware)
    result = FirmwareVerifier.verify(signed)
    assert result.valid is True
    assert result.signature_valid is True
    assert result.error is None


def test_hash_mismatch_detected_when_actual_bytes_supplied(
    firmware_signer: FirmwareSigner, sample_firmware: FirmwareImage
) -> None:
    signed = firmware_signer.sign(sample_firmware)
    tampered = sample_firmware.image_bytes + b"\xff"
    result = FirmwareVerifier.verify(signed, actual_bytes=tampered)
    assert result.valid is False
    assert result.hash_consistent is False
    assert "hash mismatch" in (result.error or "")


def test_signature_tamper_detected(
    firmware_signer: FirmwareSigner, sample_firmware: FirmwareImage
) -> None:
    signed = firmware_signer.sign(sample_firmware)
    # Flip a byte in the signature
    sig_bytes = bytearray(bytes.fromhex(signed.signature))
    sig_bytes[0] ^= 0xFF
    signed.signature = sig_bytes.hex()
    result = FirmwareVerifier.verify(signed)
    assert result.valid is False
    assert result.signature_valid is False


def test_key_ring_check_passes_for_trusted(
    firmware_signer: FirmwareSigner,
    sample_firmware: FirmwareImage,
    trusted_key_ring: KeyRing,
) -> None:
    signed = firmware_signer.sign(sample_firmware)
    result = FirmwareVerifier.verify(signed, key_ring=trusted_key_ring)
    assert result.valid is True
    assert result.key_trusted is True


def test_untrusted_signer_rejected_via_key_ring(
    sample_firmware: FirmwareImage,
    rogue_identity,  # type: ignore[no-untyped-def]
    trusted_key_ring: KeyRing,
) -> None:
    rogue_signer = FirmwareSigner(rogue_identity)
    signed = rogue_signer.sign(sample_firmware)

    result = FirmwareVerifier.verify(signed, key_ring=trusted_key_ring)
    assert result.valid is False
    assert result.key_trusted is False
    assert "not trusted" in (result.error or "")

    with pytest.raises(FirmwareVerificationError):
        FirmwareVerifier.verify_or_raise(signed, key_ring=trusted_key_ring)
