"""Tests for GovernanceNode and NodeRegistry."""

from __future__ import annotations

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_ai_governance import (
    GovernanceNode,
    GovernanceProposal,
    NodeRegistry,
    ProposalKind,
    UnknownNodeError,
    VoteDecision,
)


def _fresh_proposal(proposer_did: str) -> GovernanceProposal:
    return GovernanceProposal.create(
        kind=ProposalKind.AUTHORIZE_MODEL,
        subject_id="did:pqaid:model-x",
        title="Authorize model-x",
        proposer_did=proposer_did,
    )


def test_sign_proposal_populates_signature_fields(alice: GovernanceNode) -> None:
    proposal = _fresh_proposal(alice.did)
    alice.sign_proposal(proposal)
    assert proposal.signer_did == alice.did
    assert proposal.algorithm != ""
    assert proposal.signature != ""
    assert proposal.public_key != ""


def test_verify_proposal_true_for_valid(alice: GovernanceNode) -> None:
    proposal = _fresh_proposal(alice.did)
    alice.sign_proposal(proposal)
    assert GovernanceNode.verify_proposal(proposal) is True


def test_cast_vote_returns_signed_vote_with_valid_signature(
    alice: GovernanceNode,
) -> None:
    proposal = _fresh_proposal(alice.did)
    alice.sign_proposal(proposal)
    signed = alice.cast_vote(proposal, VoteDecision.APPROVE, rationale="looks good")
    assert signed.vote.voter_did == alice.did
    assert signed.vote.decision == VoteDecision.APPROVE
    assert signed.signature != ""
    assert GovernanceNode.verify_vote(signed) is True


def test_verify_vote_false_for_tampered(alice: GovernanceNode) -> None:
    proposal = _fresh_proposal(alice.did)
    alice.sign_proposal(proposal)
    signed = alice.cast_vote(proposal, VoteDecision.APPROVE)
    # Tamper with the rationale so canonical bytes change
    signed.vote.rationale = "TAMPERED"
    assert GovernanceNode.verify_vote(signed) is False


def test_node_registry_crud_and_weight_sum(
    alice: GovernanceNode, bob: GovernanceNode, dave: GovernanceNode
) -> None:
    reg = NodeRegistry()
    reg.register(alice)
    reg.register(bob)
    reg.register(dave)
    assert len(reg) == 3
    assert reg.is_member(alice.did)
    assert reg.total_weight() == 1 + 1 + 2
    got = reg.get(dave.did)
    assert got.did == dave.did
    reg.remove(bob.did)
    assert not reg.is_member(bob.did)
    with pytest.raises(UnknownNodeError):
        reg.get("did:pqaid:nobody")
    with pytest.raises(UnknownNodeError):
        reg.remove("did:pqaid:nobody")


def test_new_governance_node_via_agent_identity() -> None:
    node = GovernanceNode(identity=AgentIdentity.create("mallory"), name="mallory")
    assert node.did.startswith("did:pqaid:")
    assert node.weight == 1
