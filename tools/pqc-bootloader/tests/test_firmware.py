"""Tests for FirmwareImage / FirmwareMetadata / SignedFirmware."""

from __future__ import annotations

from pqc_bootloader.firmware import (
    FirmwareImage,
    FirmwareMetadata,
    SignedFirmware,
    TargetDevice,
)


def test_hash_bytes_deterministic() -> None:
    data = b"hello firmware"
    assert FirmwareImage.hash_bytes(data) == FirmwareImage.hash_bytes(data)
    assert len(FirmwareImage.hash_bytes(data)) == 64  # SHA3-256 hex


def test_image_hash_changes_with_content(sample_metadata: FirmwareMetadata) -> None:
    a = FirmwareImage.from_bytes(sample_metadata, b"content-A")
    b = FirmwareImage.from_bytes(sample_metadata, b"content-B")
    assert a.image_hash != b.image_hash


def test_from_bytes_populates_fields(
    sample_metadata: FirmwareMetadata, sample_firmware_bytes: bytes
) -> None:
    fw = FirmwareImage.from_bytes(sample_metadata, sample_firmware_bytes)
    assert fw.image_size == len(sample_firmware_bytes)
    assert fw.image_hash == FirmwareImage.hash_bytes(sample_firmware_bytes)
    assert fw.image_bytes == sample_firmware_bytes
    assert fw.metadata.name == sample_metadata.name


def test_signed_firmware_roundtrip(sample_firmware: FirmwareImage) -> None:
    sf = SignedFirmware(
        firmware=sample_firmware,
        manufacturer_key_id="kid" + "0" * 61,
        signer_did="did:pqaid:deadbeef",
        algorithm="ML-DSA-65",
        signature="ab" * 32,
        public_key="cd" * 32,
        signed_at="2026-04-20T00:00:00Z",
    )

    # with image
    d_with = sf.to_dict(include_image=True)
    assert "image_base64" in d_with["firmware"]
    restored = SignedFirmware.from_dict(d_with)
    assert restored.firmware.image_bytes == sample_firmware.image_bytes
    assert restored.firmware.image_hash == sample_firmware.image_hash
    assert restored.signer_did == sf.signer_did
    assert restored.firmware.metadata.target == TargetDevice.AI_INFERENCE_APPLIANCE

    # without image
    d_without = sf.to_dict(include_image=False)
    assert "image_base64" not in d_without["firmware"]
    restored2 = SignedFirmware.from_dict(d_without)
    assert restored2.firmware.image_bytes == b""
    assert restored2.firmware.image_hash == sample_firmware.image_hash


def test_canonical_manifest_bytes_deterministic(sample_firmware: FirmwareImage) -> None:
    a = sample_firmware.canonical_manifest_bytes()
    b = sample_firmware.canonical_manifest_bytes()
    assert a == b
    # changing the image should change the manifest (via image_hash)
    modified = FirmwareImage.from_bytes(
        sample_firmware.metadata, sample_firmware.image_bytes + b"\x00"
    )
    assert modified.canonical_manifest_bytes() != a
