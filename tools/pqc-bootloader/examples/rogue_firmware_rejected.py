"""Example: rogue actor signs a firmware, appliance rejects it.

The appliance's KeyRing only trusts the legitimate manufacturer. When an
attacker distributes a correctly-signed-but-untrusted firmware image, the
verifier refuses it and the audit log records a reject entry.
"""

from __future__ import annotations

from quantumshield.identity.agent import AgentIdentity

from pqc_bootloader import (
    BootAttestationLog,
    FirmwareImage,
    FirmwareMetadata,
    FirmwareSigner,
    FirmwareVerifier,
    KeyRing,
    TargetDevice,
)


def main() -> None:
    # Legitimate manufacturer (trusted).
    manufacturer = AgentIdentity.create("acme-appliance-vendor")
    key_ring = KeyRing()
    key_ring.add(
        public_key_hex=manufacturer.signing_keypair.public_key.hex(),
        algorithm=manufacturer.signing_keypair.algorithm.value,
        manufacturer="Acme Appliances Inc.",
    )

    # Attacker with their own key (NOT in the key ring).
    attacker = AgentIdentity.create("rogue-attacker")
    rogue_signer = FirmwareSigner(attacker)

    image_bytes = b"\x7fELF" + b"malicious payload" * 64
    metadata = FirmwareMetadata(
        name="acme-inference-os",
        version="1.2.4",  # attacker claims to be a legitimate update
        target=TargetDevice.AI_INFERENCE_APPLIANCE,
    )
    firmware = FirmwareImage.from_bytes(metadata, image_bytes)
    signed = rogue_signer.sign(firmware)
    print(f"[attacker] signed malicious firmware {firmware.metadata.name} v{firmware.metadata.version}")
    print(f"[attacker]   rogue key-id = {signed.manufacturer_key_id[:24]}...")

    # Appliance verifier refuses.
    result = FirmwareVerifier.verify(
        signed,
        actual_bytes=image_bytes,
        key_ring=key_ring,
    )
    print(
        f"[appliance] verify: valid={result.valid} trusted={result.key_trusted}"
    )
    print(f"[appliance] error: {result.error}")

    log = BootAttestationLog()
    log.log_reject(
        firmware_name=signed.firmware.metadata.name,
        firmware_version=signed.firmware.metadata.version,
        firmware_hash=signed.firmware.image_hash,
        reason=result.error or "untrusted signer",
        device_id="device-0001",
    )
    print(f"[audit] rejects={len(log.entries(decision='reject'))}")


if __name__ == "__main__":
    main()
