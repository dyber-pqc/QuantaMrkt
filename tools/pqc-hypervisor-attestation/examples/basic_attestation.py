"""Basic attestation example.

Registers two memory regions (model weights + activation cache) in the
in-memory backend, signs an AttestationReport with ML-DSA, and verifies
it from scratch — the minimum working flow.
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
    # 1. Build an attester identity with an ML-DSA keypair.
    identity = AgentIdentity.create(
        name="llama-host-attester",
        capabilities=["attest"],
    )
    attester = Attester(identity)

    # 2. Register two in-memory regions with content.
    backend = InMemoryBackend()
    weights = MemoryRegion(
        region_id="model-weights-0",
        description="Llama weight shard 0",
        address=0x1000,
        size=128,
        protection="RO",
    )
    cache = MemoryRegion(
        region_id="activation-cache",
        description="KV cache for in-flight request",
        address=0x2000,
        size=64,
        protection="RW",
    )
    weights_bytes = b"\xaa" * 128
    cache_bytes = b"\xbb" * 64
    backend.register(WORKLOAD_ID, weights, weights_bytes)
    backend.register(WORKLOAD_ID, cache, cache_bytes)

    # 3. Pin expected hashes computed at VM boot.
    expected = {
        weights.region_id: RegionSnapshot.hash_bytes(weights_bytes),
        cache.region_id: RegionSnapshot.hash_bytes(cache_bytes),
    }

    # 4. Attest once.
    loop = ContinuousAttester(
        attester=attester,
        backend=backend,
        workload_id=WORKLOAD_ID,
        expected_hashes=expected,
    )
    report = loop.attest_once()
    print(f"signed report    : {report.report_id}")
    print(f"attester did     : {report.signer_did}")
    print(f"algorithm        : {report.algorithm}")
    print(f"claims           : {len(report.claims)}")

    # 5. Verify.
    result = AttestationVerifier.verify(report, strict=True)
    print(f"valid            : {result.valid}")
    print(f"signature_valid  : {result.signature_valid}")
    print(f"not_expired      : {result.not_expired}")
    print(f"drifts           : {result.drifts}")


if __name__ == "__main__":
    main()
