"""Example: emergency freeze of all agent actions.

All five governance nodes approve an ``EMERGENCY_FREEZE`` proposal. A signed
``ConsensusResult`` is produced and its ML-DSA signature is independently
verified.
"""

from __future__ import annotations

from quantumshield.identity.agent import AgentIdentity

from pqc_ai_governance import (
    ConsensusRound,
    GovernanceNode,
    GovernanceProposal,
    NodeRegistry,
    ProposalKind,
    QuorumPolicy,
    VoteDecision,
)


def main() -> None:
    print("== PQC AI Governance: Emergency Freeze ==\n")

    alice = GovernanceNode(identity=AgentIdentity.create("alice"), name="alice", weight=1)
    bob = GovernanceNode(identity=AgentIdentity.create("bob"), name="bob", weight=1)
    carol = GovernanceNode(identity=AgentIdentity.create("carol"), name="carol", weight=1)
    dave = GovernanceNode(identity=AgentIdentity.create("dave"), name="dave", weight=2)
    eve = GovernanceNode(identity=AgentIdentity.create("eve"), name="eve", weight=1)

    registry = NodeRegistry()
    for node in (alice, bob, carol, dave, eve):
        registry.register(node)

    proposal = GovernanceProposal.create(
        kind=ProposalKind.EMERGENCY_FREEZE,
        subject_id="*",
        title="EMERGENCY: halt all agent actions",
        description="Suspected credential compromise; freeze all agents immediately.",
        proposer_did=alice.did,
        parameters={"severity": "critical", "reason": "suspected-compromise"},
        ttl_seconds=3600,
    )
    alice.sign_proposal(proposal)
    print(f"Proposal {proposal.proposal_id}")
    print(f"  title : {proposal.title}")
    print(f"  kind  : {proposal.kind.value}")

    rnd = ConsensusRound(proposal=proposal, registry=registry, policy=QuorumPolicy())
    for voter in (alice, bob, carol, dave, eve):
        signed = voter.cast_vote(
            proposal,
            VoteDecision.APPROVE,
            rationale=f"{voter.name} approves emergency freeze",
        )
        rnd.cast(signed)
        print(f"  {voter.name:5s} -> APPROVE (weight {voter.weight})")

    result = rnd.finalize(coordinator=alice)
    print("\nConsensus:")
    print(f"  decision : {result.decision}")
    print(f"  reason   : {result.reason}")
    print(f"  approve  : {result.approve_weight}/{result.total_weight}")

    ok = ConsensusRound.verify_result(result)
    print(f"  signature: {'OK (ML-DSA verified)' if ok else 'INVALID'}")
    assert ok, "result signature failed to verify"

    print("\n[FREEZE IN EFFECT] All agents must halt.")
    print(f"  signed-by : {result.signer_did[:22]}... ({result.algorithm})")


if __name__ == "__main__":
    main()
