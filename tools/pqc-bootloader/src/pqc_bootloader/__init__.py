"""PQC Bootloader - quantum-safe signed-boot for AI appliances."""

from pqc_bootloader.errors import (
    BootloaderError,
    FirmwareRollbackError,
    FirmwareVerificationError,
    KeyRingError,
    MeasuredBootError,
    UnknownKeyError,
    UpdateChainError,
)
from pqc_bootloader.firmware import (
    FirmwareImage,
    FirmwareMetadata,
    SignedFirmware,
    TargetDevice,
)
from pqc_bootloader.signer import (
    FirmwareSigner,
    FirmwareVerifier,
    VerificationResult,
)
from pqc_bootloader.key_ring import KeyRing, KeyRingEntry
from pqc_bootloader.update_chain import UpdateChain
from pqc_bootloader.measured_boot import (
    BootStage,
    MeasuredBoot,
    PCRMeasurement,
)
from pqc_bootloader.audit import BootAttemptEntry, BootAttestationLog

__version__ = "0.1.0"
__all__ = [
    "FirmwareImage",
    "FirmwareMetadata",
    "SignedFirmware",
    "TargetDevice",
    "FirmwareSigner",
    "FirmwareVerifier",
    "VerificationResult",
    "KeyRing",
    "KeyRingEntry",
    "UpdateChain",
    "MeasuredBoot",
    "PCRMeasurement",
    "BootStage",
    "BootAttestationLog",
    "BootAttemptEntry",
    "BootloaderError",
    "FirmwareVerificationError",
    "UnknownKeyError",
    "UpdateChainError",
    "MeasuredBootError",
    "KeyRingError",
    "FirmwareRollbackError",
]
