"""Tests for ConsensusRound + QuorumPolicy."""

from __future__ import annotations

import time

import pytest

from pqc_ai_governance import (
    ConsensusRound,
    GovernanceNode,
    GovernanceProposal,
    NodeRegistry,
    ProposalExpiredError,
    ProposalKind,
    ProposalStatus,
    QuorumPolicy,
    VoteDecision,
)


def test_quorum_passes_with_four_of_five_approvals(
    nodes: list[GovernanceNode],
    registry: NodeRegistry,
    sample_proposal: GovernanceProposal,
) -> None:
    rnd = ConsensusRound(proposal=sample_proposal, registry=registry)
    alice, bob, carol, dave, eve = nodes
    for voter in (alice, bob, carol, dave):
        rnd.cast(voter.cast_vote(sample_proposal, VoteDecision.APPROVE))
    rnd.cast(eve.cast_vote(sample_proposal, VoteDecision.REJECT))

    result = rnd.finalize(alice)
    assert result.decision == "passed"
    assert sample_proposal.status == ProposalStatus.PASSED


def test_quorum_fails_with_only_two_of_five(
    nodes: list[GovernanceNode],
    registry: NodeRegistry,
    sample_proposal: GovernanceProposal,
) -> None:
    rnd = ConsensusRound(proposal=sample_proposal, registry=registry)
    alice, bob, *_ = nodes
    rnd.cast(alice.cast_vote(sample_proposal, VoteDecision.APPROVE))
    rnd.cast(bob.cast_vote(sample_proposal, VoteDecision.APPROVE))
    result = rnd.finalize(alice)
    assert result.decision == "rejected"
    assert "participation" in result.reason


def test_quorum_fails_when_all_abstain(
    nodes: list[GovernanceNode],
    registry: NodeRegistry,
    sample_proposal: GovernanceProposal,
) -> None:
    rnd = ConsensusRound(proposal=sample_proposal, registry=registry)
    for voter in nodes:
        rnd.cast(voter.cast_vote(sample_proposal, VoteDecision.ABSTAIN))
    result = rnd.finalize(nodes[0])
    assert result.decision == "rejected"
    assert "abstain" in result.reason.lower()


def test_expired_proposal_cast_raises(
    alice: GovernanceNode,
    registry: NodeRegistry,
) -> None:
    proposal = GovernanceProposal.create(
        kind=ProposalKind.EMERGENCY_FREEZE,
        subject_id="*",
        title="freeze",
        proposer_did=alice.did,
        ttl_seconds=0,
    )
    alice.sign_proposal(proposal)
    rnd = ConsensusRound(proposal=proposal, registry=registry)
    time.sleep(0.01)
    with pytest.raises(ProposalExpiredError):
        rnd.cast(alice.cast_vote(proposal, VoteDecision.APPROVE))


def test_finalize_signs_result(
    nodes: list[GovernanceNode],
    registry: NodeRegistry,
    sample_proposal: GovernanceProposal,
) -> None:
    rnd = ConsensusRound(proposal=sample_proposal, registry=registry)
    for voter in nodes:
        rnd.cast(voter.cast_vote(sample_proposal, VoteDecision.APPROVE))
    result = rnd.finalize(nodes[0])
    assert result.signer_did == nodes[0].did
    assert result.signature != ""
    assert result.public_key != ""
    assert result.algorithm != ""


def test_verify_result_true_for_valid(
    nodes: list[GovernanceNode],
    registry: NodeRegistry,
    sample_proposal: GovernanceProposal,
) -> None:
    rnd = ConsensusRound(
        proposal=sample_proposal, registry=registry, policy=QuorumPolicy()
    )
    for voter in nodes:
        rnd.cast(voter.cast_vote(sample_proposal, VoteDecision.APPROVE))
    result = rnd.finalize(nodes[0])
    assert ConsensusRound.verify_result(result) is True
    # Tampered result should fail verification
    result.reason = "TAMPERED"
    assert ConsensusRound.verify_result(result) is False
