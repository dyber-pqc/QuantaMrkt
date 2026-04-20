"""Tests for ContinuousAttester."""

from __future__ import annotations

from pqc_hypervisor_attestation import (
    Attester,
    ContinuousAttester,
    InMemoryBackend,
)

WORKLOAD_ID = "model-serving-1"


def test_attest_once_covers_all_regions(
    attester: Attester, backend: InMemoryBackend
) -> None:
    loop = ContinuousAttester(
        attester=attester, backend=backend, workload_id=WORKLOAD_ID
    )
    report = loop.attest_once()
    assert report.signature
    region_ids = {c.region.region_id for c in report.claims}
    assert region_ids == {"model-weights-0", "activation-cache"}
    assert report.platform == "in-memory"


def test_run_for_returns_expected_count(
    attester: Attester, backend: InMemoryBackend
) -> None:
    loop = ContinuousAttester(
        attester=attester, backend=backend, workload_id=WORKLOAD_ID
    )
    # seconds=2, interval=1.0 -> expect ~2 reports; allow 1..3 for clock jitter.
    reports = loop.run_for(seconds=2, interval=1.0)
    assert 1 <= len(reports) <= 3
    for r in reports:
        assert r.signature


def test_drift_between_calls_changes_snapshot_hash(
    attester: Attester, backend: InMemoryBackend
) -> None:
    loop = ContinuousAttester(
        attester=attester, backend=backend, workload_id=WORKLOAD_ID
    )
    first = loop.attest_once()
    # Mutate the weights to simulate tampering.
    backend.update("model-weights-0", b"\xcc" * 128)
    second = loop.attest_once()

    def weights_hash(report) -> str:
        for claim in report.claims:
            if claim.region.region_id == "model-weights-0":
                return claim.snapshot.content_hash
        raise AssertionError("weights region not in report")

    assert weights_hash(first) != weights_hash(second)
