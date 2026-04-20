"""Tests for Attester and AttestationVerifier."""

from __future__ import annotations

import time

import pytest

from pqc_hypervisor_attestation import (
    AttestationClaim,
    AttestationReport,
    AttestationVerifier,
    Attester,
    MemoryRegion,
    RegionSnapshot,
)
from pqc_hypervisor_attestation.errors import AttestationVerificationError


def _make_report() -> AttestationReport:
    region = MemoryRegion(
        region_id="w0",
        description="weights",
        address=0x1000,
        size=4,
        protection="RO",
    )
    snap = RegionSnapshot.create("w0", b"\x00\x01\x02\x03")
    claim = AttestationClaim.create(region=region, snapshot=snap)
    return AttestationReport.create(claims=[claim], ttl_seconds=60)


def test_sign_populates_fields(attester: Attester) -> None:
    report = _make_report()
    signed = attester.sign(report)
    assert signed.signature
    assert signed.public_key
    assert signed.algorithm
    assert signed.signer_did == attester.identity.did


def test_verify_success(attester: Attester) -> None:
    report = attester.sign(_make_report())
    result = AttestationVerifier.verify(report)
    assert result.valid is True
    assert result.signature_valid is True
    assert result.not_expired is True
    assert result.drifts == []


def test_signature_tamper_detected(attester: Attester) -> None:
    report = attester.sign(_make_report())
    # Flip the first hex char of the signature — that invalidates the sig
    # even under Ed25519 transitional mode.
    first = report.signature[0]
    flipped = "f" if first != "f" else "0"
    report.signature = flipped + report.signature[1:]
    result = AttestationVerifier.verify(report)
    assert result.signature_valid is False
    assert result.valid is False


def test_expired_report_rejected(attester: Attester) -> None:
    region = MemoryRegion(
        region_id="w0",
        description="weights",
        address=0x1000,
        size=4,
        protection="RO",
    )
    snap = RegionSnapshot.create("w0", b"\x00\x01\x02\x03")
    claim = AttestationClaim.create(region=region, snapshot=snap)
    report = AttestationReport.create(claims=[claim], ttl_seconds=0)
    signed = attester.sign(report)
    time.sleep(0.1)
    result = AttestationVerifier.verify(signed)
    assert result.signature_valid is True
    assert result.not_expired is False
    assert result.valid is False


def test_verify_or_raise_raises_on_failure(attester: Attester) -> None:
    report = attester.sign(_make_report())
    # Tamper
    report.signature = "00" * len(bytes.fromhex(report.signature))
    with pytest.raises(AttestationVerificationError):
        AttestationVerifier.verify_or_raise(report)


def test_missing_signature_rejected() -> None:
    report = _make_report()  # unsigned
    result = AttestationVerifier.verify(report)
    assert result.signature_valid is False
    assert result.valid is False
    assert result.error == "missing signature"
