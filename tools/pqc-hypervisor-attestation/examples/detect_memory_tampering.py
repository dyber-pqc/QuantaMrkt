"""Detect in-VM memory tampering.

Attest clean state, mutate a region (simulating an attacker rewriting model
weights), attest again — the verifier must flag drift on the second report.
"""

from __future__ import annotations

from quantumshield.identity.agent import AgentIdentity

from pqc_hypervisor_attestation import (
    AttestationVerifier,
    Attester,
    ContinuousAttester,
    InMemoryBackend,
    MemoryRegion,
    RegionSnapshot,
)

WORKLOAD_ID = "model-serving-1"


def main() -> None:
    identity = AgentIdentity.create(
        name="tamper-detector",
        capabilities=["attest"],
    )
    attester = Attester(identity)

    backend = InMemoryBackend()
    weights = MemoryRegion(
        region_id="model-weights-0",
        description="Llama weight shard 0",
        address=0x1000,
        size=32,
        protection="RO",
    )
    trusted = b"MODEL-WEIGHTS-TRUSTED-PAYLOAD-01"
    backend.register(WORKLOAD_ID, weights, trusted)

    loop = ContinuousAttester(
        attester=attester,
        backend=backend,
        workload_id=WORKLOAD_ID,
        expected_hashes={weights.region_id: RegionSnapshot.hash_bytes(trusted)},
    )

    # 1. Clean attestation.
    clean = loop.attest_once()
    clean_result = AttestationVerifier.verify(clean, strict=True)
    print("[clean]")
    print(f"  valid   : {clean_result.valid}")
    print(f"  drifts  : {clean_result.drifts}")

    # 2. Simulated attacker tampering.
    backend.update(weights.region_id, b"MODEL-WEIGHTS-COMPROMISED!!!!!!!")

    # 3. Tampered attestation.
    dirty = loop.attest_once()
    dirty_result = AttestationVerifier.verify(dirty, strict=True)
    print("[tampered]")
    print(f"  valid            : {dirty_result.valid}")
    print(f"  signature_valid  : {dirty_result.signature_valid}")
    print(f"  drifts           : {dirty_result.drifts}")
    print(f"  error            : {dirty_result.error}")


if __name__ == "__main__":
    main()
