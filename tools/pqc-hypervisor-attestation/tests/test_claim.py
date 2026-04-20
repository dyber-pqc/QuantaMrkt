"""Tests for AttestationClaim and AttestationReport."""

from __future__ import annotations

import time

from pqc_hypervisor_attestation import (
    AttestationClaim,
    AttestationReport,
    MemoryRegion,
    RegionSnapshot,
)


def _region() -> MemoryRegion:
    return MemoryRegion(
        region_id="w0",
        description="weights",
        address=0x1000,
        size=4,
        protection="RO",
    )


def _snapshot() -> RegionSnapshot:
    return RegionSnapshot.create("w0", b"\x00\x01\x02\x03")


def test_create_populates_ids() -> None:
    claim = AttestationClaim.create(region=_region(), snapshot=_snapshot())
    assert claim.claim_id.startswith("urn:pqc-att:")
    report = AttestationReport.create(claims=[claim])
    assert report.report_id.startswith("urn:pqc-attreport:")
    assert report.issued_at
    assert report.expires_at


def test_to_dict_from_dict_roundtrip() -> None:
    claim = AttestationClaim.create(
        region=_region(),
        snapshot=_snapshot(),
        expected_hash="abc",
        workload_id="w",
        platform="in-memory",
        nonce="n",
    )
    report = AttestationReport.create(
        claims=[claim],
        attester_id="did:example:1",
        platform="in-memory",
    )
    restored = AttestationReport.from_dict(report.to_dict())
    assert restored.report_id == report.report_id
    assert len(restored.claims) == 1
    assert restored.claims[0].claim_id == claim.claim_id
    assert restored.claims[0].region == claim.region
    assert restored.claims[0].snapshot == claim.snapshot
    assert restored.attester_id == "did:example:1"


def test_is_expired_respects_ttl() -> None:
    claim = AttestationClaim.create(region=_region(), snapshot=_snapshot())
    fresh = AttestationReport.create(claims=[claim], ttl_seconds=60)
    assert fresh.is_expired() is False

    stale = AttestationReport.create(claims=[claim], ttl_seconds=0)
    time.sleep(0.05)
    assert stale.is_expired() is True


def test_canonical_bytes_deterministic() -> None:
    claim = AttestationClaim.create(
        region=_region(),
        snapshot=_snapshot(),
        expected_hash="abc",
        workload_id="w",
        platform="in-memory",
        nonce="n",
    )
    report = AttestationReport.create(claims=[claim])
    a = report.canonical_bytes()
    b = report.canonical_bytes()
    assert a == b
    # Ordering of keys must be stable regardless of dict insertion order
    assert a.startswith(b'{"attester_id":')
