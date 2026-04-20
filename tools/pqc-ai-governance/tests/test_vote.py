"""Tests for Vote and SignedVote."""

from __future__ import annotations

from pqc_ai_governance import SignedVote, Vote, VoteDecision


def test_create_populates_fields() -> None:
    vote = Vote.create(
        proposal_id="urn:pqc-gov-prop:x",
        proposal_hash="deadbeef",
        voter_did="did:pqaid:alice",
        decision=VoteDecision.APPROVE,
        rationale="looks good",
    )
    assert vote.vote_id.startswith("urn:pqc-gov-vote:")
    assert vote.decision == VoteDecision.APPROVE
    assert vote.rationale == "looks good"
    assert vote.cast_at != ""


def test_canonical_bytes_is_deterministic() -> None:
    vote = Vote.create(
        proposal_id="p1",
        proposal_hash="h1",
        voter_did="did:pqaid:alice",
        decision=VoteDecision.REJECT,
    )
    assert vote.canonical_bytes() == vote.canonical_bytes()


def test_signed_vote_roundtrip() -> None:
    vote = Vote.create(
        proposal_id="p1",
        proposal_hash="h1",
        voter_did="did:pqaid:alice",
        decision=VoteDecision.ABSTAIN,
    )
    sv = SignedVote(vote=vote, algorithm="ML-DSA-65", signature="aa", public_key="bb")
    restored = SignedVote.from_dict(sv.to_dict())
    assert restored.vote.vote_id == vote.vote_id
    assert restored.vote.decision == VoteDecision.ABSTAIN
    assert restored.algorithm == "ML-DSA-65"
    assert restored.signature == "aa"


def test_decision_preserved_through_serialization() -> None:
    for decision in (VoteDecision.APPROVE, VoteDecision.REJECT, VoteDecision.ABSTAIN):
        vote = Vote.create(
            proposal_id="p",
            proposal_hash="h",
            voter_did="did:pqaid:alice",
            decision=decision,
        )
        sv = SignedVote(vote=vote, algorithm="x", signature="", public_key="")
        round_tripped = SignedVote.from_dict(sv.to_dict())
        assert round_tripped.vote.decision == decision
