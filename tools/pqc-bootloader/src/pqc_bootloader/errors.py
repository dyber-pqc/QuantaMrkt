"""Exception hierarchy for pqc-bootloader."""

from __future__ import annotations


class BootloaderError(Exception):
    """Base exception for all pqc-bootloader errors."""


class FirmwareVerificationError(BootloaderError):
    """Raised when a SignedFirmware fails cryptographic verification."""


class UnknownKeyError(BootloaderError):
    """Raised when a referenced key is not present in the KeyRing."""


class UpdateChainError(BootloaderError):
    """Raised when an UpdateChain link breaks continuity."""


class MeasuredBootError(BootloaderError):
    """Raised when a measured-boot PCR chain is inconsistent."""


class KeyRingError(BootloaderError):
    """Raised for KeyRing-level faults (duplicate add, malformed key)."""


class FirmwareRollbackError(UpdateChainError):
    """Raised when attempting to roll the chain back to an older version."""
