"""Intel TDX backend (stub interface).

Real integration uses ``/dev/tdx-guest`` via the Intel TDX kernel module.
This stub documents the expected shape; users plug in their real syscalls.

A production implementation of this backend is expected to:

* Enumerate guest-physical memory ranges inside the TD (trust domain) that
  cover the confidential workload, usually derived from the TDX module's
  MRTD / RTMR measurements at build time.
* Issue a ``TDX_CMD_GET_REPORT0`` ioctl on ``/dev/tdx-guest`` per region and
  compute a SHA3-256 hash of the page contents.
* Return ``MemoryRegion`` / ``RegionSnapshot`` values whose ``address``
  and ``size`` match the actual guest-physical ranges inside the TD.
"""

from __future__ import annotations

from pqc_hypervisor_attestation.backends.base import AttestationBackend
from pqc_hypervisor_attestation.errors import BackendError
from pqc_hypervisor_attestation.region import MemoryRegion, RegionSnapshot


class IntelTDXBackend(AttestationBackend):
    """Stub Intel TDX backend.

    Raises :class:`BackendError` when invoked without real kernel wiring.
    """

    name = "intel-tdx"
    platform = "intel-tdx"

    def __init__(self, device_path: str = "/dev/tdx-guest") -> None:
        self.device_path = device_path

    def list_regions(self, workload_id: str) -> list[MemoryRegion]:
        raise BackendError(
            "IntelTDXBackend is a stub. Provide a real implementation that reads "
            f"the workload's TD measurement from {self.device_path} and translates "
            "guest-physical memory pages into MemoryRegion entries."
        )

    def snapshot(self, region: MemoryRegion) -> RegionSnapshot:
        raise BackendError(
            "IntelTDXBackend.snapshot is a stub. A real implementation issues "
            "a TDX_CMD_GET_REPORT0 ioctl to attest the region's current state."
        )
