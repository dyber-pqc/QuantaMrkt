"""Tests for expected_hash drift detection."""

from __future__ import annotations

import pytest

from pqc_hypervisor_attestation import (
    AttestationClaim,
    AttestationReport,
    AttestationVerifier,
    Attester,
    MemoryRegion,
    RegionSnapshot,
)
from pqc_hypervisor_attestation.errors import RegionDriftError


def _signed_report(
    attester: Attester,
    content: bytes,
    expected: str,
) -> AttestationReport:
    region = MemoryRegion(
        region_id="w0",
        description="weights",
        address=0x1000,
        size=len(content),
        protection="RO",
    )
    snap = RegionSnapshot.create("w0", content)
    claim = AttestationClaim.create(
        region=region,
        snapshot=snap,
        expected_hash=expected,
    )
    report = AttestationReport.create(claims=[claim], ttl_seconds=60)
    return attester.sign(report)


def test_matching_expected_hash_verifies(attester: Attester) -> None:
    content = b"trusted-weights"
    expected = RegionSnapshot.hash_bytes(content)
    report = _signed_report(attester, content, expected)
    result = AttestationVerifier.verify(report)
    assert result.valid is True
    assert result.drifts == []


def test_drift_fails_in_strict_mode(attester: Attester) -> None:
    expected = RegionSnapshot.hash_bytes(b"trusted-weights")
    # Real snapshot taken over tampered bytes.
    report = _signed_report(attester, b"TAMPERED-weights", expected)
    result = AttestationVerifier.verify(report, strict=True)
    assert result.signature_valid is True
    assert result.drifts == ["w0"]
    assert result.valid is False
    with pytest.raises(RegionDriftError):
        AttestationVerifier.verify_or_raise(report, strict=True)


def test_drift_allowed_in_non_strict_mode(attester: Attester) -> None:
    expected = RegionSnapshot.hash_bytes(b"trusted-weights")
    report = _signed_report(attester, b"TAMPERED-weights", expected)
    result = AttestationVerifier.verify(report, strict=False)
    assert result.valid is True
    assert result.drifts == ["w0"]
