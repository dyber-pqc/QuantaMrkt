"""ContinuousAttester — periodic attestation loop."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from pqc_hypervisor_attestation.backends.base import AttestationBackend
from pqc_hypervisor_attestation.claim import AttestationClaim, AttestationReport
from pqc_hypervisor_attestation.signer import Attester


@dataclass
class ContinuousAttester:
    """Produce a fresh signed AttestationReport every N seconds.

    In production this runs in a daemon thread inside the workload process.
    For testing and tight loops, call :meth:`attest_once` directly.
    """

    attester: Attester
    backend: AttestationBackend
    workload_id: str
    expected_hashes: dict[str, str] = field(default_factory=dict)   # region_id -> expected_hash
    ttl_seconds: int = 300

    def attest_once(self, nonce: str | None = None) -> AttestationReport:
        """Enumerate regions, snapshot each, build and sign a report."""
        nonce = nonce or os.urandom(16).hex()
        regions = self.backend.list_regions(self.workload_id)
        claims: list[AttestationClaim] = []
        for region in regions:
            snapshot = self.backend.snapshot(region)
            expected = self.expected_hashes.get(region.region_id, "")
            claims.append(
                AttestationClaim.create(
                    region=region,
                    snapshot=snapshot,
                    expected_hash=expected,
                    workload_id=self.workload_id,
                    platform=self.backend.platform,
                    nonce=nonce,
                )
            )
        report = AttestationReport.create(
            claims=claims,
            attester_id=self.attester.identity.did,
            platform=self.backend.platform,
            ttl_seconds=self.ttl_seconds,
        )
        return self.attester.sign(report)

    def run_for(
        self,
        seconds: int,
        interval: float = 1.0,
        on_report: Callable[[AttestationReport], None] | None = None,
    ) -> list[AttestationReport]:
        """Run the attestation loop for a bounded number of seconds.

        Returns the list of reports produced. Intended for tests / demos.
        Production deployments wire this into a systemd timer or equivalent.
        """
        reports: list[AttestationReport] = []
        end = time.time() + seconds
        while time.time() < end:
            report = self.attest_once()
            reports.append(report)
            if on_report:
                on_report(report)
            time.sleep(interval)
        return reports
