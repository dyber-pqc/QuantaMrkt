"""Exception hierarchy for pqc-ebpf-attestation."""

from __future__ import annotations


class BPFAttestationError(Exception):
    """Base exception for all pqc-ebpf-attestation errors."""


class ProgramNotFoundError(BPFAttestationError):
    """Raised when an eBPF program file or reference cannot be located."""


class SignatureVerificationError(BPFAttestationError):
    """Raised when a SignedBPFProgram fails ML-DSA signature verification."""


class ProgramHashMismatchError(SignatureVerificationError):
    """Raised when the bytecode hash does not match the signed manifest."""


class PolicyDeniedError(BPFAttestationError):
    """Raised when a LoadPolicy denies a program from being loaded."""


class UntrustedSignerError(PolicyDeniedError):
    """Raised when the signer DID is not in the policy allow-list."""
