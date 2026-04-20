"""Shared fixtures for pqc-ai-governance tests."""

from __future__ import annotations

import pytest

from quantumshield.identity.agent import AgentIdentity

from pqc_ai_governance import (
    GovernanceNode,
    GovernanceProposal,
    NodeRegistry,
    ProposalKind,
)


@pytest.fixture
def alice() -> GovernanceNode:
    return GovernanceNode(identity=AgentIdentity.create("alice"), name="alice", weight=1)


@pytest.fixture
def bob() -> GovernanceNode:
    return GovernanceNode(identity=AgentIdentity.create("bob"), name="bob", weight=1)


@pytest.fixture
def carol() -> GovernanceNode:
    return GovernanceNode(identity=AgentIdentity.create("carol"), name="carol", weight=1)


@pytest.fixture
def dave() -> GovernanceNode:
    return GovernanceNode(identity=AgentIdentity.create("dave"), name="dave", weight=2)


@pytest.fixture
def eve() -> GovernanceNode:
    return GovernanceNode(identity=AgentIdentity.create("eve"), name="eve", weight=1)


@pytest.fixture
def nodes(
    alice: GovernanceNode,
    bob: GovernanceNode,
    carol: GovernanceNode,
    dave: GovernanceNode,
    eve: GovernanceNode,
) -> list[GovernanceNode]:
    return [alice, bob, carol, dave, eve]


@pytest.fixture
def registry(nodes: list[GovernanceNode]) -> NodeRegistry:
    reg = NodeRegistry()
    for n in nodes:
        reg.register(n)
    return reg


@pytest.fixture
def sample_proposal(alice: GovernanceNode) -> GovernanceProposal:
    proposal = GovernanceProposal.create(
        kind=ProposalKind.AUTHORIZE_MODEL,
        subject_id="did:pqaid:medical-ai-v2",
        title="Authorize medical-ai-v2",
        proposer_did=alice.did,
        description="Permit medical-ai-v2 to run in production.",
        parameters={"environment": "prod", "max_rate_qps": 50},
    )
    return alice.sign_proposal(proposal)
