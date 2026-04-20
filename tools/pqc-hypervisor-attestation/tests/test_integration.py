"""End-to-end integration tests."""

from __future__ import annotations

from pqc_hypervisor_attestation import (
    AttestationVerifier,
    Attester,
    ContinuousAttester,
    InMemoryBackend,
    RegionSnapshot,
)

WORKLOAD_ID = "model-serving-1"


def test_full_flow_register_attest_verify(
    attester: Attester, backend: InMemoryBackend
) -> None:
    loop = ContinuousAttester(
        attester=attester, backend=backend, workload_id=WORKLOAD_ID
    )
    # Pin the expected hashes for both regions.
    loop.expected_hashes = {
        "model-weights-0": RegionSnapshot.hash_bytes(b"\xaa" * 128),
        "activation-cache": RegionSnapshot.hash_bytes(b"\xbb" * 64),
    }
    report = loop.attest_once()
    result = AttestationVerifier.verify(report, strict=True)
    assert result.valid is True
    assert result.drifts == []


def test_tampered_region_flagged_after_attestation(
    attester: Attester, backend: InMemoryBackend
) -> None:
    loop = ContinuousAttester(
        attester=attester, backend=backend, workload_id=WORKLOAD_ID
    )
    loop.expected_hashes = {
        "model-weights-0": RegionSnapshot.hash_bytes(b"\xaa" * 128),
        "activation-cache": RegionSnapshot.hash_bytes(b"\xbb" * 64),
    }

    # First attestation: clean.
    ok_report = loop.attest_once()
    assert AttestationVerifier.verify(ok_report, strict=True).valid is True

    # Simulated attacker mutates weights in place.
    backend.update("model-weights-0", b"\xff" * 128)

    # Next attestation: drift detected via expected_hash vs new snapshot.
    drift_report = loop.attest_once()
    result = AttestationVerifier.verify(drift_report, strict=True)
    assert result.signature_valid is True
    assert "model-weights-0" in result.drifts
    assert result.valid is False
