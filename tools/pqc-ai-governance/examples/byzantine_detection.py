"""Example: Byzantine double-voting is detected at tally time.

One node (Eve) attempts to double-vote with *conflicting* decisions on the
same proposal. The ``VoteTally`` raises ``ByzantineDetectedError`` the moment
the second conflicting vote is submitted, and the audit log captures the
violation.
"""

from __future__ import annotations

from quantumshield.identity.agent import AgentIdentity

from pqc_ai_governance import (
    ByzantineDetectedError,
    GovernanceAuditLog,
    GovernanceNode,
    GovernanceProposal,
    NodeRegistry,
    ProposalKind,
    VoteDecision,
    VoteTally,
)


def main() -> None:
    print("== PQC AI Governance: Byzantine Double-Vote Detection ==\n")

    alice = GovernanceNode(identity=AgentIdentity.create("alice"), name="alice")
    bob = GovernanceNode(identity=AgentIdentity.create("bob"), name="bob")
    eve = GovernanceNode(identity=AgentIdentity.create("eve"), name="eve")

    registry = NodeRegistry()
    for n in (alice, bob, eve):
        registry.register(n)

    proposal = GovernanceProposal.create(
        kind=ProposalKind.UPDATE_POLICY,
        subject_id="policy:rate-limit",
        title="Raise rate limit to 100 QPS",
        proposer_did=alice.did,
    )
    alice.sign_proposal(proposal)

    audit = GovernanceAuditLog()
    audit.log_proposal_created(proposal)

    tally = VoteTally(proposal=proposal, registry=registry)

    # Honest votes first.
    alice_vote = alice.cast_vote(proposal, VoteDecision.APPROVE)
    bob_vote = bob.cast_vote(proposal, VoteDecision.APPROVE)
    tally.add(alice_vote)
    audit.log_vote_cast(alice_vote)
    tally.add(bob_vote)
    audit.log_vote_cast(bob_vote)
    print(f"alice -> {alice_vote.vote.decision.value}")
    print(f"bob   -> {bob_vote.vote.decision.value}")

    # Eve votes once.
    eve_first = eve.cast_vote(proposal, VoteDecision.APPROVE)
    tally.add(eve_first)
    audit.log_vote_cast(eve_first)
    print(f"eve   -> {eve_first.vote.decision.value}  (first vote)")

    # Eve now tries to flip her vote with a brand-new signed ballot.
    eve_conflict = eve.cast_vote(proposal, VoteDecision.REJECT)
    print(f"eve   -> {eve_conflict.vote.decision.value}  (conflicting second vote)")

    try:
        tally.add(eve_conflict)
    except ByzantineDetectedError as exc:
        print(f"\n[!] ByzantineDetectedError raised: {exc}")
        audit.log_byzantine_detected(
            voter_did=eve.did,
            proposal_id=proposal.proposal_id,
            prior=VoteDecision.APPROVE.value,
            now=VoteDecision.REJECT.value,
        )
    else:  # pragma: no cover - should not happen
        print("unexpected: no exception raised")
        return

    print("\n-- Audit trail --")
    for entry in audit.entries():
        extra = f" decision={entry.decision}" if entry.decision else ""
        print(f"  {entry.operation:<22s} actor={entry.actor_did[:22]}...{extra}")


if __name__ == "__main__":
    main()
