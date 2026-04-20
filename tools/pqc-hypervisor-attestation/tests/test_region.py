"""Tests for MemoryRegion and RegionSnapshot."""

from __future__ import annotations

from pqc_hypervisor_attestation import MemoryRegion, RegionSnapshot


def test_snapshot_hash_is_deterministic() -> None:
    data = b"hello world"
    s1 = RegionSnapshot.create("r1", data)
    s2 = RegionSnapshot.create("r1", data)
    assert s1.content_hash == s2.content_hash
    assert s1.size == len(data)


def test_snapshot_hash_changes_with_content() -> None:
    s1 = RegionSnapshot.create("r1", b"aaaa")
    s2 = RegionSnapshot.create("r1", b"aaab")
    assert s1.content_hash != s2.content_hash


def test_memory_region_roundtrip() -> None:
    region = MemoryRegion(
        region_id="weights-0",
        description="Llama-3 weight shard 0",
        address=0x1000,
        size=4096,
        protection="RO",
    )
    data = region.to_dict()
    restored = MemoryRegion(**data)
    assert restored == region
