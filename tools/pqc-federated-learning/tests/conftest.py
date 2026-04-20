"""Pytest fixtures for pqc-federated-learning tests."""

from __future__ import annotations

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_federated_learning import (
    ClientUpdate,
    ClientUpdateMetadata,
    GradientTensor,
    UpdateSigner,
)


@pytest.fixture
def aggregator_identity() -> AgentIdentity:
    return AgentIdentity.create("test-aggregator")


@pytest.fixture
def client_a_identity() -> AgentIdentity:
    return AgentIdentity.create("client-a")


@pytest.fixture
def client_b_identity() -> AgentIdentity:
    return AgentIdentity.create("client-b")


@pytest.fixture
def client_c_identity() -> AgentIdentity:
    return AgentIdentity.create("client-c")


@pytest.fixture
def attacker_identity() -> AgentIdentity:
    return AgentIdentity.create("evil-attacker")


@pytest.fixture
def sample_tensors() -> list[GradientTensor]:
    return [
        GradientTensor(name="dense_1.weights", shape=(2, 2), values=(0.1, 0.2, 0.3, 0.4)),
        GradientTensor(name="dense_1.bias", shape=(2,), values=(0.01, 0.02)),
    ]


def make_signed_update(
    identity: AgentIdentity,
    round_id: str = "round-1",
    model_id: str = "model-x",
    num_samples: int = 100,
    values_scale: float = 1.0,
    tensors: list[GradientTensor] | None = None,
) -> ClientUpdate:
    """Factory for a signed ClientUpdate."""
    if tensors is None:
        tensors = [
            GradientTensor(
                name="dense_1.weights",
                shape=(2, 2),
                values=tuple(v * values_scale for v in (0.1, 0.2, 0.3, 0.4)),
            ),
            GradientTensor(
                name="dense_1.bias",
                shape=(2,),
                values=tuple(v * values_scale for v in (0.01, 0.02)),
            ),
        ]
    meta = ClientUpdateMetadata(
        client_did=identity.did,
        round_id=round_id,
        model_id=model_id,
        num_samples=num_samples,
    )
    update = ClientUpdate.create(meta, tensors)
    return UpdateSigner(identity).sign(update)


@pytest.fixture
def signed_update_factory():
    return make_signed_update
