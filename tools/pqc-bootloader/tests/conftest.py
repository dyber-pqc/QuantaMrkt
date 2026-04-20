"""Shared test fixtures for pqc-bootloader."""

from __future__ import annotations

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_bootloader.firmware import FirmwareImage, FirmwareMetadata, TargetDevice
from pqc_bootloader.key_ring import KeyRing
from pqc_bootloader.signer import FirmwareSigner


@pytest.fixture
def manufacturer_identity() -> AgentIdentity:
    return AgentIdentity.create("acme-appliance-vendor")


@pytest.fixture
def rogue_identity() -> AgentIdentity:
    return AgentIdentity.create("rogue-attacker")


@pytest.fixture
def firmware_signer(manufacturer_identity: AgentIdentity) -> FirmwareSigner:
    return FirmwareSigner(manufacturer_identity)


@pytest.fixture
def sample_firmware_bytes() -> bytes:
    return b"\x7fELF\x02\x01\x01\x00" + b"firmware binary payload" * 64


@pytest.fixture
def sample_metadata() -> FirmwareMetadata:
    return FirmwareMetadata(
        name="acme-inference-os",
        version="1.2.3",
        target=TargetDevice.AI_INFERENCE_APPLIANCE,
        kernel_version="6.6.12",
        architecture="x86_64",
        build_id="abc123def456",
        release_notes_url="https://acme.example/releases/1.2.3",
        min_hardware_revision="rev-C",
        security_level="production",
    )


@pytest.fixture
def sample_firmware(
    sample_metadata: FirmwareMetadata, sample_firmware_bytes: bytes
) -> FirmwareImage:
    return FirmwareImage.from_bytes(sample_metadata, sample_firmware_bytes)


@pytest.fixture
def trusted_key_ring(manufacturer_identity: AgentIdentity) -> KeyRing:
    ring = KeyRing()
    ring.add(
        public_key_hex=manufacturer_identity.signing_keypair.public_key.hex(),
        algorithm=manufacturer_identity.signing_keypair.algorithm.value,
        manufacturer="Acme Appliances Inc.",
    )
    return ring
