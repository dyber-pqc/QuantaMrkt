"""Tests for attestation backends."""

from __future__ import annotations

import pytest

from pqc_hypervisor_attestation import (
    AMDSEVSNPBackend,
    InMemoryBackend,
    IntelTDXBackend,
    MemoryRegion,
)
from pqc_hypervisor_attestation.errors import BackendError, InvalidRegionError


def test_in_memory_register_list_snapshot() -> None:
    be = InMemoryBackend()
    region = MemoryRegion(
        region_id="r1",
        description="test",
        address=0x0,
        size=4,
        protection="RO",
    )
    be.register("w", region, b"abcd")
    regions = be.list_regions("w")
    assert regions == [region]
    snap = be.snapshot(region)
    assert snap.size == 4
    assert snap.content_hash


def test_in_memory_invalid_region_raises() -> None:
    be = InMemoryBackend()
    region = MemoryRegion(
        region_id="missing",
        description="nope",
        address=0x0,
        size=0,
        protection="RO",
    )
    with pytest.raises(InvalidRegionError):
        be.snapshot(region)
    with pytest.raises(InvalidRegionError):
        be.update("missing", b"x")


def test_sev_snp_list_regions_raises() -> None:
    backend = AMDSEVSNPBackend()
    with pytest.raises(BackendError):
        backend.list_regions("any")


def test_tdx_snapshot_raises() -> None:
    backend = IntelTDXBackend()
    region = MemoryRegion(
        region_id="r1",
        description="test",
        address=0x0,
        size=4,
        protection="RO",
    )
    with pytest.raises(BackendError):
        backend.snapshot(region)


def test_workload_isolation() -> None:
    be = InMemoryBackend()
    region = MemoryRegion(
        region_id="a",
        description="test",
        address=0x0,
        size=4,
        protection="RO",
    )
    be.register("workload-a", region, b"abcd")
    assert be.list_regions("workload-a") == [region]
    assert be.list_regions("workload-b") == []
