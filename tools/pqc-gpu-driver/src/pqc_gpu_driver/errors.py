"""Exception hierarchy for pqc-gpu-driver."""

from __future__ import annotations


class GPUDriverError(Exception):
    """Base exception for all pqc-gpu-driver errors."""


class ChannelEstablishmentError(GPUDriverError):
    """Raised when the CPU<->GPU encrypted channel cannot be established."""


class ChannelExpiredError(GPUDriverError):
    """Raised when an operation is attempted on an expired ChannelSession."""


class NonceReplayError(GPUDriverError):
    """Raised when a replayed sequence number or nonce is detected."""


class DecryptionError(GPUDriverError):
    """Raised when an EncryptedTensor fails AES-GCM decryption or AAD check."""


class DriverAttestationError(GPUDriverError):
    """Raised when a DriverAttestation fails signature / hash / trust verification."""


class BackendError(GPUDriverError):
    """Raised when a GPU backend encounters an unrecoverable error
    (e.g. missing runtime, unsupported operation, stub invoked)."""
