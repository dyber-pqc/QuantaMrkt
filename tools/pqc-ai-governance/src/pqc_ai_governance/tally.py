"""VoteTally - count signed votes, detect Byzantine behavior (double-voting)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pqc_ai_governance.errors import ByzantineDetectedError
from pqc_ai_governance.node import GovernanceNode, NodeRegistry
from pqc_ai_governance.proposal import GovernanceProposal
from pqc_ai_governance.vote import SignedVote, VoteDecision


@dataclass
class VoteTally:
    """Aggregate votes for a proposal with Byzantine checks.

    Detects:
      1. Votes with invalid signatures -> recorded as invalid.
      2. Votes from non-member DIDs -> recorded as invalid.
      3. Votes referencing the wrong proposal_hash -> recorded as invalid.
      4. A single DID voting twice with different decisions -> ``ByzantineDetectedError``.
    """

    proposal: GovernanceProposal
    registry: NodeRegistry
    approve_weight: int = 0
    reject_weight: int = 0
    abstain_weight: int = 0
    _seen_voters: dict[str, VoteDecision] = field(default_factory=dict)
    valid_votes: list[SignedVote] = field(default_factory=list)
    invalid_votes: list[tuple[SignedVote, str]] = field(default_factory=list)

    def add(self, signed: SignedVote) -> None:
        vote = signed.vote

        # 1. Proposal hash check
        if vote.proposal_hash != self.proposal.proposal_hash():
            self.invalid_votes.append((signed, "proposal hash mismatch"))
            return

        # 2. Proposal id check
        if vote.proposal_id != self.proposal.proposal_id:
            self.invalid_votes.append((signed, "proposal id mismatch"))
            return

        # 3. Signature check
        if not GovernanceNode.verify_vote(signed):
            self.invalid_votes.append((signed, "invalid signature"))
            return

        # 4. Membership check
        if not self.registry.is_member(vote.voter_did):
            self.invalid_votes.append((signed, "non-member voter"))
            return

        # 5. Byzantine check: same voter voting differently
        if vote.voter_did in self._seen_voters:
            prior = self._seen_voters[vote.voter_did]
            if prior != vote.decision:
                raise ByzantineDetectedError(
                    f"voter {vote.voter_did} cast conflicting votes: "
                    f"{prior.value} then {vote.decision.value}"
                )
            # Same decision, same voter - silent idempotent skip
            return

        self._seen_voters[vote.voter_did] = vote.decision
        node = self.registry.get(vote.voter_did)
        weight = node.weight

        if vote.decision == VoteDecision.APPROVE:
            self.approve_weight += weight
        elif vote.decision == VoteDecision.REJECT:
            self.reject_weight += weight
        else:
            self.abstain_weight += weight

        self.valid_votes.append(signed)

    def total_cast_weight(self) -> int:
        return self.approve_weight + self.reject_weight + self.abstain_weight

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal.proposal_id,
            "approve_weight": self.approve_weight,
            "reject_weight": self.reject_weight,
            "abstain_weight": self.abstain_weight,
            "valid_vote_count": len(self.valid_votes),
            "invalid_vote_count": len(self.invalid_votes),
        }
