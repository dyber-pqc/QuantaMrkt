"""Exception hierarchy for pqc-enclave-sdk."""

from __future__ import annotations


class EnclaveSDKError(Exception):
    """Base exception for all pqc-enclave-sdk errors."""


class UnknownArtifactError(EnclaveSDKError):
    """Named or id-addressed artifact does not exist in the enclave vault."""


class EnclaveLockedError(EnclaveSDKError):
    """Operation requires an unlocked enclave vault; call unlock() first."""


class DecryptionError(EnclaveSDKError):
    """AES-GCM decryption failed - likely tampered ciphertext or wrong key."""


class BackendError(EnclaveSDKError):
    """Underlying platform backend (iOS / Android / QSEE) refused or failed."""


class AttestationError(EnclaveSDKError):
    """Device attestation signature is invalid or malformed."""


class PolicyViolationError(EnclaveSDKError):
    """Caller bundle / biometric / rate-limit policy rejected the request."""
