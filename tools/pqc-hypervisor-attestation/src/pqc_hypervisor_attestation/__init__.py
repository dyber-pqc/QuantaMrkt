"""PQC Hypervisor Attestation — quantum-safe memory integrity for AI workloads."""

from pqc_hypervisor_attestation.backends.base import AttestationBackend
from pqc_hypervisor_attestation.backends.memory import InMemoryBackend
from pqc_hypervisor_attestation.backends.sev_snp import AMDSEVSNPBackend
from pqc_hypervisor_attestation.backends.tdx import IntelTDXBackend
from pqc_hypervisor_attestation.claim import AttestationClaim, AttestationReport
from pqc_hypervisor_attestation.continuous import ContinuousAttester
from pqc_hypervisor_attestation.errors import (
    AttestationVerificationError,
    BackendError,
    HypervisorAttestationError,
    InvalidRegionError,
    RegionDriftError,
    UnknownBackendError,
)
from pqc_hypervisor_attestation.region import MemoryRegion, RegionSnapshot
from pqc_hypervisor_attestation.signer import (
    Attester,
    AttestationVerifier,
    VerificationResult,
)

__version__ = "0.1.0"
__all__ = [
    "MemoryRegion",
    "RegionSnapshot",
    "AttestationClaim",
    "AttestationReport",
    "Attester",
    "AttestationVerifier",
    "VerificationResult",
    "ContinuousAttester",
    "AttestationBackend",
    "InMemoryBackend",
    "AMDSEVSNPBackend",
    "IntelTDXBackend",
    "HypervisorAttestationError",
    "InvalidRegionError",
    "AttestationVerificationError",
    "BackendError",
    "UnknownBackendError",
    "RegionDriftError",
]
