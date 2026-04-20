"""PQC eBPF Attestation - ML-DSA load gate for eBPF programs."""

from pqc_ebpf_attestation.errors import (
    BPFAttestationError,
    PolicyDeniedError,
    ProgramHashMismatchError,
    ProgramNotFoundError,
    SignatureVerificationError,
    UntrustedSignerError,
)
from pqc_ebpf_attestation.program import (
    BPFProgram,
    BPFProgramMetadata,
    BPFProgramType,
)
from pqc_ebpf_attestation.signer import (
    BPFSigner,
    BPFVerifier,
    SignedBPFProgram,
    VerificationResult,
)
from pqc_ebpf_attestation.policy import (
    LoadPolicy,
    PolicyDecision,
    PolicyRule,
)
from pqc_ebpf_attestation.audit import (
    AttestationLog,
    AttestationLogEntry,
)

__version__ = "0.1.0"
__all__ = [
    "BPFProgram",
    "BPFProgramMetadata",
    "BPFProgramType",
    "BPFSigner",
    "BPFVerifier",
    "VerificationResult",
    "SignedBPFProgram",
    "LoadPolicy",
    "PolicyRule",
    "PolicyDecision",
    "AttestationLog",
    "AttestationLogEntry",
    "BPFAttestationError",
    "ProgramNotFoundError",
    "SignatureVerificationError",
    "PolicyDeniedError",
    "UntrustedSignerError",
    "ProgramHashMismatchError",
]
