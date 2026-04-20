"""Shared pytest fixtures."""

from __future__ import annotations

import os

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_gpu_driver import DriverAttester, DriverModule


@pytest.fixture
def signer_identity() -> AgentIdentity:
    """A generic signer identity used as the default driver attester."""
    return AgentIdentity.create("test-driver-signer", capabilities=["attest"])


@pytest.fixture
def trusted_identity() -> AgentIdentity:
    """An identity that is on the verifier's trusted allow-list."""
    return AgentIdentity.create("trusted-gpu-vendor", capabilities=["attest"])


@pytest.fixture
def untrusted_identity() -> AgentIdentity:
    """An identity NOT on the verifier's trusted allow-list."""
    return AgentIdentity.create("rogue-driver-author", capabilities=["attest"])


@pytest.fixture
def attester(signer_identity: AgentIdentity) -> DriverAttester:
    return DriverAttester(signer_identity)


@pytest.fixture
def sample_module_bytes() -> bytes:
    """Deterministic 4KB blob that stands in for a .ko driver module."""
    return b"\x00NVIDIA-GPU-DRV\x00" + b"\xaa" * (4096 - 16)


@pytest.fixture
def sample_module(sample_module_bytes: bytes) -> DriverModule:
    return DriverModule(
        name="nvidia.ko",
        version="550.54.14",
        module_hash=DriverModule.hash_module_bytes(sample_module_bytes),
        module_size=len(sample_module_bytes),
        target="linux",
    )


@pytest.fixture
def random_tensor_bytes() -> bytes:
    """1 KiB of random bytes to use as a fake tensor payload."""
    return os.urandom(1024)
