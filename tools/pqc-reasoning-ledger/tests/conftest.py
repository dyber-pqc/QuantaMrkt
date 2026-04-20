"""Shared pytest fixtures for pqc-reasoning-ledger."""

from __future__ import annotations

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_reasoning_ledger import ReasoningRecorder


@pytest.fixture
def signer_identity() -> AgentIdentity:
    return AgentIdentity.create("test-reasoning-signer")


@pytest.fixture
def recorder(signer_identity: AgentIdentity) -> ReasoningRecorder:
    return ReasoningRecorder(signer_identity)


@pytest.fixture
def sample_trace_started(recorder: ReasoningRecorder) -> ReasoningRecorder:
    recorder.begin_trace(
        model_did="did:pqaid:test-model",
        model_version="1.0",
        task="unit-test",
        domain="test",
    )
    return recorder
