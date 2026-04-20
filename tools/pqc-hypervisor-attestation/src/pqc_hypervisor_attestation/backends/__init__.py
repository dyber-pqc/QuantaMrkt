"""Attestation backends."""

from __future__ import annotations

from pqc_hypervisor_attestation.backends.base import AttestationBackend
from pqc_hypervisor_attestation.backends.memory import InMemoryBackend
from pqc_hypervisor_attestation.backends.sev_snp import AMDSEVSNPBackend
from pqc_hypervisor_attestation.backends.tdx import IntelTDXBackend

__all__ = [
    "AttestationBackend",
    "InMemoryBackend",
    "AMDSEVSNPBackend",
    "IntelTDXBackend",
]
