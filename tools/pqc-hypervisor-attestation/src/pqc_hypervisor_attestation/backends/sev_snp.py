"""AMD SEV-SNP backend (stub interface).

Real integration uses ``/dev/sev-guest`` via the ``sev-snp`` kernel module.
This stub documents the expected shape; users plug in their real syscalls.

A production implementation of this backend is expected to:

* Enumerate guest-physical memory ranges the confidential workload owns,
  usually by reading the SEV-SNP launch measurement and combining it with
  static manifest data produced at VM boot.
* Issue an ``SNP_GET_REPORT`` ioctl on ``/dev/sev-guest`` per region and
  compute a SHA3-256 hash of the page contents.
* Return ``MemoryRegion`` / ``RegionSnapshot`` values whose ``address``
  and ``size`` match the actual guest-physical ranges.
"""

from __future__ import annotations

from pqc_hypervisor_attestation.backends.base import AttestationBackend
from pqc_hypervisor_attestation.errors import BackendError
from pqc_hypervisor_attestation.region import MemoryRegion, RegionSnapshot


class AMDSEVSNPBackend(AttestationBackend):
    """Stub AMD SEV-SNP backend.

    Raises :class:`BackendError` when invoked without real kernel wiring.
    """

    name = "amd-sev-snp"
    platform = "amd-sev-snp"

    def __init__(self, device_path: str = "/dev/sev-guest") -> None:
        self.device_path = device_path

    def list_regions(self, workload_id: str) -> list[MemoryRegion]:
        raise BackendError(
            "AMDSEVSNPBackend is a stub. Provide a real implementation that reads "
            f"the workload's launch digest from {self.device_path} and translates "
            "guest-physical memory pages into MemoryRegion entries."
        )

    def snapshot(self, region: MemoryRegion) -> RegionSnapshot:
        raise BackendError(
            "AMDSEVSNPBackend.snapshot is a stub. A real implementation issues "
            "an SNP_GET_REPORT ioctl to attest the region's current state."
        )
