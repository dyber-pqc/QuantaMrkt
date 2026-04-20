"""Attestation backend interface.

A backend knows how to (1) enumerate MemoryRegions for a workload and
(2) snapshot a region's bytes into a RegionSnapshot. The library is
backend-agnostic — real implementations wrap AMD SEV-SNP, Intel TDX, or
userland ptrace-based shims.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from pqc_hypervisor_attestation.region import MemoryRegion, RegionSnapshot


class AttestationBackend(ABC):
    """Base class all attestation backends inherit from."""

    name: str = ""
    platform: str = ""                   # "amd-sev-snp" | "intel-tdx" | "in-memory" | ...

    @abstractmethod
    def list_regions(self, workload_id: str) -> list[MemoryRegion]:
        """Return the memory regions the workload owns."""

    @abstractmethod
    def snapshot(self, region: MemoryRegion) -> RegionSnapshot:
        """Take a fresh SHA3-256 snapshot of the region's current bytes."""
