"""In-memory backend — reference implementation for tests and demos."""

from __future__ import annotations

from pqc_hypervisor_attestation.backends.base import AttestationBackend
from pqc_hypervisor_attestation.errors import InvalidRegionError
from pqc_hypervisor_attestation.region import MemoryRegion, RegionSnapshot


class InMemoryBackend(AttestationBackend):
    """Deterministic in-memory backend.

    Holds region bytes in a dict keyed by ``region_id``. Suitable for
    tests, tutorials, and CI — it has no dependency on any TEE hardware.
    """

    name = "in-memory"
    platform = "in-memory"

    def __init__(self) -> None:
        self._regions: dict[str, MemoryRegion] = {}
        self._contents: dict[str, bytes] = {}
        self._workload_map: dict[str, list[str]] = {}   # workload_id -> [region_id]

    def register(self, workload_id: str, region: MemoryRegion, content: bytes) -> None:
        """Register a region with initial content for the given workload."""
        self._regions[region.region_id] = region
        self._contents[region.region_id] = content
        ids = self._workload_map.setdefault(workload_id, [])
        if region.region_id not in ids:
            ids.append(region.region_id)

    def update(self, region_id: str, new_content: bytes) -> None:
        """Overwrite a region's bytes to simulate a legitimate mutation
        (or an attacker tampering with memory)."""
        if region_id not in self._regions:
            raise InvalidRegionError(f"no region with id {region_id}")
        self._contents[region_id] = new_content

    def list_regions(self, workload_id: str) -> list[MemoryRegion]:
        ids = self._workload_map.get(workload_id, [])
        return [self._regions[rid] for rid in ids]

    def snapshot(self, region: MemoryRegion) -> RegionSnapshot:
        if region.region_id not in self._contents:
            raise InvalidRegionError(
                f"region {region.region_id} not registered"
            )
        return RegionSnapshot.create(
            region.region_id, self._contents[region.region_id]
        )
