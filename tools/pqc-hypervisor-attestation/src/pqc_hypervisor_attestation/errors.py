"""Exception hierarchy for pqc-hypervisor-attestation."""

from __future__ import annotations


class HypervisorAttestationError(Exception):
    """Base exception for all pqc-hypervisor-attestation errors."""


class InvalidRegionError(HypervisorAttestationError):
    """Raised when a memory region is missing, malformed, or not registered."""


class AttestationVerificationError(HypervisorAttestationError):
    """Raised when an AttestationReport fails cryptographic verification."""


class BackendError(HypervisorAttestationError):
    """Raised when an attestation backend cannot service a request."""


class UnknownBackendError(BackendError):
    """Raised when a requested backend platform is not registered."""


class RegionDriftError(AttestationVerificationError):
    """Raised when a region's snapshot does not match its expected hash."""
