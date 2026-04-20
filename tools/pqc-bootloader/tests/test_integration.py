"""End-to-end integration tests."""

from __future__ import annotations

from quantumshield.identity.agent import AgentIdentity

from pqc_bootloader.audit import BootAttestationLog
from pqc_bootloader.firmware import FirmwareImage
from pqc_bootloader.key_ring import KeyRing
from pqc_bootloader.measured_boot import BootStage, MeasuredBoot
from pqc_bootloader.signer import FirmwareSigner, FirmwareVerifier


def test_full_boot_flow_accepted(
    firmware_signer: FirmwareSigner,
    sample_firmware: FirmwareImage,
    trusted_key_ring: KeyRing,
) -> None:
    # 1. Manufacturer signs firmware at the factory.
    signed = firmware_signer.sign(sample_firmware)

    # 2. Appliance boot ROM verifies signature + key-ring trust.
    result = FirmwareVerifier.verify(
        signed,
        actual_bytes=sample_firmware.image_bytes,
        key_ring=trusted_key_ring,
    )
    assert result.valid is True
    assert result.hash_consistent is True
    assert result.key_trusted is True
    assert result.signature_valid is True

    # 3. Measured boot extends through rom, bootloader, kernel, initrd.
    mb = MeasuredBoot()
    mb.extend(BootStage.ROM, b"rom-v1")
    mb.extend(BootStage.BOOTLOADER, b"bootloader-v1")
    mb.extend(BootStage.KERNEL, b"kernel-v1")
    mb.extend(BootStage.INITRD, b"initrd-v1")
    assert len(mb.measurements) == 4
    assert mb.pcr_value != "0" * 64

    # 4. Audit log records the acceptance.
    log = BootAttestationLog()
    entry = log.log_accept(
        firmware_name=signed.firmware.metadata.name,
        firmware_version=signed.firmware.metadata.version,
        firmware_hash=signed.firmware.image_hash,
        device_id="device-0001",
        pcr_value_after=mb.pcr_value,
    )
    assert entry.decision == "accept"
    assert entry.pcr_value_after == mb.pcr_value
    assert len(log.entries(decision="accept")) == 1


def test_rejected_firmware_path(
    sample_firmware: FirmwareImage,
    trusted_key_ring: KeyRing,
) -> None:
    # Rogue identity signs firmware; key ring does NOT trust it.
    rogue = AgentIdentity.create("rogue-attacker")
    rogue_signer = FirmwareSigner(rogue)
    signed = rogue_signer.sign(sample_firmware)

    result = FirmwareVerifier.verify(
        signed,
        actual_bytes=sample_firmware.image_bytes,
        key_ring=trusted_key_ring,
    )
    assert result.valid is False
    assert result.key_trusted is False

    log = BootAttestationLog()
    entry = log.log_reject(
        firmware_name=signed.firmware.metadata.name,
        firmware_version=signed.firmware.metadata.version,
        firmware_hash=signed.firmware.image_hash,
        reason=result.error or "untrusted key",
        device_id="device-0001",
    )
    assert entry.decision == "reject"
    assert "not trusted" in entry.reason
    assert len(log.entries(decision="reject")) == 1
