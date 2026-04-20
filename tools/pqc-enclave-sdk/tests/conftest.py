"""Pytest fixtures for pqc-enclave-sdk."""

from __future__ import annotations

import os

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_enclave_sdk import (
    EnclaveVault,
    InMemoryEnclaveBackend,
)


@pytest.fixture
def signer_identity() -> AgentIdentity:
    return AgentIdentity.create("test-device-signer")


@pytest.fixture
def backend() -> InMemoryEnclaveBackend:
    return InMemoryEnclaveBackend(
        device_id="iphone-alice-test",
        device_model="iphone-15-pro",
    )


@pytest.fixture
def vault(backend: InMemoryEnclaveBackend) -> EnclaveVault:
    v = EnclaveVault(backend=backend)
    v.unlock()
    return v


@pytest.fixture
def small_weights() -> bytes:
    return os.urandom(512)


@pytest.fixture
def api_credential() -> bytes:
    return b"sk-test-abc"
