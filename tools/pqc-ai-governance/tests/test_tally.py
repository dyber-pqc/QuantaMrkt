"""Tests for VoteTally (Byzantine-aware vote aggregation)."""

from __future__ import annotations

import pytest

from pqc_ai_governance import (
    ByzantineDetectedError,
    GovernanceNode,
    GovernanceProposal,
    NodeRegistry,
    SignedVote,
    Vote,
    VoteDecision,
    VoteTally,
)


def test_approve_vote_increments_approve_weight(
    alice: GovernanceNode,
    registry: NodeRegistry,
    sample_proposal: GovernanceProposal,
) -> None:
    tally = VoteTally(proposal=sample_proposal, registry=registry)
    tally.add(alice.cast_vote(sample_proposal, VoteDecision.APPROVE))
    assert tally.approve_weight == 1
    assert tally.reject_weight == 0


def test_reject_vote_increments_reject_weight(
    dave: GovernanceNode,
    registry: NodeRegistry,
    sample_proposal: GovernanceProposal,
) -> None:
    tally = VoteTally(proposal=sample_proposal, registry=registry)
    tally.add(dave.cast_vote(sample_proposal, VoteDecision.REJECT))
    # dave has weight 2
    assert tally.reject_weight == 2
    assert tally.approve_weight == 0


def test_invalid_signature_rejected_and_recorded(
    alice: GovernanceNode,
    registry: NodeRegistry,
    sample_proposal: GovernanceProposal,
) -> None:
    tally = VoteTally(proposal=sample_proposal, registry=registry)
    signed = alice.cast_vote(sample_proposal, VoteDecision.APPROVE)
    signed.vote.rationale = "TAMPERED"
    tally.add(signed)
    assert tally.approve_weight == 0
    assert len(tally.invalid_votes) == 1
    assert tally.invalid_votes[0][1] == "invalid signature"


def test_wrong_proposal_hash_rejected(
    alice: GovernanceNode,
    registry: NodeRegistry,
    sample_proposal: GovernanceProposal,
) -> None:
    tally = VoteTally(proposal=sample_proposal, registry=registry)
    bogus = Vote.create(
        proposal_id=sample_proposal.proposal_id,
        proposal_hash="0" * 64,  # wrong
        voter_did=alice.did,
        decision=VoteDecision.APPROVE,
    )
    tally.add(SignedVote(vote=bogus, algorithm="x", signature="", public_key=""))
    assert len(tally.invalid_votes) == 1
    assert tally.invalid_votes[0][1] == "proposal hash mismatch"


def test_non_member_voter_rejected(
    registry: NodeRegistry,
    sample_proposal: GovernanceProposal,
) -> None:
    from quantumshield.identity.agent import AgentIdentity

    intruder = GovernanceNode(
        identity=AgentIdentity.create("mallory"), name="mallory"
    )
    # Deliberately do NOT register the intruder
    signed = intruder.cast_vote(sample_proposal, VoteDecision.APPROVE)
    tally = VoteTally(proposal=sample_proposal, registry=registry)
    tally.add(signed)
    assert tally.approve_weight == 0
    assert len(tally.invalid_votes) == 1
    assert tally.invalid_votes[0][1] == "non-member voter"


def test_double_vote_same_decision_is_idempotent(
    alice: GovernanceNode,
    registry: NodeRegistry,
    sample_proposal: GovernanceProposal,
) -> None:
    tally = VoteTally(proposal=sample_proposal, registry=registry)
    tally.add(alice.cast_vote(sample_proposal, VoteDecision.APPROVE))
    tally.add(alice.cast_vote(sample_proposal, VoteDecision.APPROVE))
    assert tally.approve_weight == 1
    assert len(tally.valid_votes) == 1


def test_double_vote_different_decisions_raises(
    alice: GovernanceNode,
    registry: NodeRegistry,
    sample_proposal: GovernanceProposal,
) -> None:
    tally = VoteTally(proposal=sample_proposal, registry=registry)
    tally.add(alice.cast_vote(sample_proposal, VoteDecision.APPROVE))
    with pytest.raises(ByzantineDetectedError):
        tally.add(alice.cast_vote(sample_proposal, VoteDecision.REJECT))
