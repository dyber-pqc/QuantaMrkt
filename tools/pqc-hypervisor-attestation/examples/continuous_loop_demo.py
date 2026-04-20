"""ContinuousAttester demo.

Runs the attestation loop for a few seconds and prints a one-line summary
per produced report. Production deployments would hook this into a systemd
timer or a sidecar daemon and stream reports to a remote verifier.
"""

from __future__ import annotations

from quantumshield.identity.agent import AgentIdentity

from pqc_hypervisor_attestation import (
    AttestationReport,
    Attester,
    ContinuousAttester,
    InMemoryBackend,
    MemoryRegion,
    RegionSnapshot,
)

WORKLOAD_ID = "model-serving-1"


def main() -> None:
    identity = AgentIdentity.create(
        name="continuous-attester",
        capabilities=["attest"],
    )
    attester = Attester(identity)

    backend = InMemoryBackend()
    weights = MemoryRegion(
        region_id="model-weights-0",
        description="Llama weight shard 0",
        address=0x1000,
        size=64,
        protection="RO",
    )
    content = b"\xaa" * 64
    backend.register(WORKLOAD_ID, weights, content)

    loop = ContinuousAttester(
        attester=attester,
        backend=backend,
        workload_id=WORKLOAD_ID,
        expected_hashes={weights.region_id: RegionSnapshot.hash_bytes(content)},
    )

    def on_report(report: AttestationReport) -> None:
        claim = report.claims[0]
        print(
            f"issued={report.issued_at} "
            f"region={claim.region.region_id} "
            f"hash={claim.snapshot.content_hash[:12]}... "
            f"claims={len(report.claims)}"
        )

    reports = loop.run_for(seconds=3, interval=1.0, on_report=on_report)
    print(f"\ntotal reports produced: {len(reports)}")


if __name__ == "__main__":
    main()
