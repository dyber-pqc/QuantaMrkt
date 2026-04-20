"""Shared pytest fixtures."""

from __future__ import annotations

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_hypervisor_attestation import (
    Attester,
    InMemoryBackend,
    MemoryRegion,
)

WORKLOAD_ID = "model-serving-1"


@pytest.fixture
def attester_identity() -> AgentIdentity:
    return AgentIdentity.create("test-attester", capabilities=["attest"])


@pytest.fixture
def attester(attester_identity: AgentIdentity) -> Attester:
    return Attester(attester_identity)


@pytest.fixture
def backend() -> InMemoryBackend:
    be = InMemoryBackend()
    weights = MemoryRegion(
        region_id="model-weights-0",
        description="Llama weights shard 0",
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
    be.register(WORKLOAD_ID, weights, b"\xaa" * 128)
    be.register(WORKLOAD_ID, cache, b"\xbb" * 64)
    return be
