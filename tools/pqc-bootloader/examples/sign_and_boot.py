"""Example: manufacturer signs firmware, appliance boots and accepts it.

Flow:
  1. Manufacturer creates a signing identity and signs the firmware image.
  2. Appliance owner pre-loads the manufacturer public key into the KeyRing.
  3. On boot, the appliance runs FirmwareVerifier against actual image bytes
     and the key-ring.
  4. Measured-boot chain extends through 4 stages (bootloader, kernel, initrd,
     userspace) producing a final PCR value.
  5. Audit log records the accept decision with the final PCR.
"""

from __future__ import annotations

from quantumshield.identity.agent import AgentIdentity

from pqc_bootloader import (
    BootAttestationLog,
    BootStage,
    FirmwareImage,
    FirmwareMetadata,
    FirmwareSigner,
    FirmwareVerifier,
    KeyRing,
    MeasuredBoot,
    TargetDevice,
)


def main() -> None:
    # --- manufacturer side -----------------------------------------------
    manufacturer = AgentIdentity.create("acme-appliance-vendor")
    signer = FirmwareSigner(manufacturer)

    image_bytes = b"\x7fELF" + b"payload bytes for inference OS" * 32
    metadata = FirmwareMetadata(
        name="acme-inference-os",
        version="1.2.3",
        target=TargetDevice.AI_INFERENCE_APPLIANCE,
        kernel_version="6.6.12",
        architecture="x86_64",
        build_id="ci-2026-04-20-a1b2c3",
    )
    firmware = FirmwareImage.from_bytes(metadata, image_bytes)
    signed = signer.sign(firmware)
    print(f"[factory] signed firmware {firmware.metadata.name} v{firmware.metadata.version}")
    print(f"[factory]   image hash    = {firmware.image_hash[:24]}...")
    print(f"[factory]   key-id        = {signed.manufacturer_key_id[:24]}...")
    print(f"[factory]   algorithm     = {signed.algorithm}")

    # --- appliance side --------------------------------------------------
    key_ring = KeyRing()
    key_ring.add(
        public_key_hex=manufacturer.signing_keypair.public_key.hex(),
        algorithm=manufacturer.signing_keypair.algorithm.value,
        manufacturer="Acme Appliances Inc.",
    )
    print(f"[appliance] key-ring trusts {len(key_ring)} manufacturer key(s)")

    result = FirmwareVerifier.verify(
        signed,
        actual_bytes=image_bytes,
        key_ring=key_ring,
    )
    print(
        f"[appliance] verify: valid={result.valid} "
        f"signature={result.signature_valid} "
        f"hash={result.hash_consistent} trusted={result.key_trusted}"
    )

    if not result.valid:
        print(f"[appliance] REJECT: {result.error}")
        return

    # --- measured boot ---------------------------------------------------
    mb = MeasuredBoot()
    mb.extend(BootStage.BOOTLOADER, b"bootloader-image-bytes")
    mb.extend(BootStage.KERNEL, b"kernel-image-bytes")
    mb.extend(BootStage.INITRD, b"initrd-image-bytes")
    mb.extend(BootStage.USERSPACE, b"userspace-image-bytes")
    print(f"[appliance] measured boot final PCR = {mb.pcr_value[:24]}...")
    for m in mb.measurements:
        print(f"[appliance]   stage={m.stage.value:10s} hash={m.measured_hash[:16]}...")

    # --- audit log -------------------------------------------------------
    log = BootAttestationLog()
    log.log_accept(
        firmware_name=signed.firmware.metadata.name,
        firmware_version=signed.firmware.metadata.version,
        firmware_hash=signed.firmware.image_hash,
        device_id="device-0001",
        pcr_value_after=mb.pcr_value,
    )
    print(f"[audit] accepts={len(log.entries(decision='accept'))}")


if __name__ == "__main__":
    main()
