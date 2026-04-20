"""End-to-end integration tests for pqc-ai-governance."""

from __future__ import annotations

import pytest

from pqc_ai_governance import (
    AuthorizationChain,
    AuthorizationGrant,
    ByzantineDetectedError,
    ConsensusRound,
    GovernanceAuditLog,
    GovernanceNode,
    GovernanceProposal,
    NodeRegistry,
    ProposalKind,
    ProposalStatus,
    QuorumPolicy,
    VoteDecision,
    VoteTally,
)


def test_happy_path_authorize_model(
    nodes: list[GovernanceNode],
    registry: NodeRegistry,
    sample_proposal: GovernanceProposal,
) -> None:
    alice, bob, carol, dave, eve = nodes

    rnd = ConsensusRound(proposal=sample_proposal, registry=registry)
    # 4 approvals, 1 reject => 5 approve-weight (alice+bob+carol+dave=1+1+1+2), 1 reject
    for voter in (alice, bob, carol, dave):
        rnd.cast(voter.cast_vote(sample_proposal, VoteDecision.APPROVE))
    rnd.cast(eve.cast_vote(sample_proposal, VoteDecision.REJECT))

    result = rnd.finalize(alice)
    assert result.decision == "passed"
    assert sample_proposal.status == ProposalStatus.PASSED
    assert ConsensusRound.verify_result(result) is True

    # Now bind the passing proposal into an authorization chain.
    chain = AuthorizationChain(subject_id=sample_proposal.subject_id)
    chain.add(
        AuthorizationGrant(
            subject_id=sample_proposal.subject_id,
            kind=sample_proposal.kind,
            result=result,
        )
    )
    assert chain.is_authorized(ProposalKind.AUTHORIZE_MODEL) is True


def test_byzantine_detection(
    nodes: list[GovernanceNode],
    registry: NodeRegistry,
    sample_proposal: GovernanceProposal,
) -> None:
    alice, _, _, _, eve = nodes
    tally = VoteTally(proposal=sample_proposal, registry=registry)
    tally.add(eve.cast_vote(sample_proposal, VoteDecision.APPROVE))
    with pytest.raises(ByzantineDetectedError):
        tally.add(eve.cast_vote(sample_proposal, VoteDecision.REJECT))


def test_no_quorum_path(
    nodes: list[GovernanceNode],
    registry: NodeRegistry,
    sample_proposal: GovernanceProposal,
) -> None:
    alice, bob, *_ = nodes
    rnd = ConsensusRound(
        proposal=sample_proposal,
        registry=registry,
        policy=QuorumPolicy(),
    )
    rnd.cast(alice.cast_vote(sample_proposal, VoteDecision.APPROVE))
    rnd.cast(bob.cast_vote(sample_proposal, VoteDecision.APPROVE))

    # Audit: log every vote cast, plus the eventual outcome
    audit = GovernanceAuditLog()
    audit.log_proposal_created(sample_proposal)
    for sv in rnd.tally.valid_votes:
        audit.log_vote_cast(sv)

    result = rnd.finalize(alice)
    audit.log_consensus_reached(result)

    assert result.decision == "rejected"
    assert "participation" in result.reason
    assert sample_proposal.status == ProposalStatus.REJECTED
    assert any(e.operation == "consensus_reached" for e in audit.entries())
