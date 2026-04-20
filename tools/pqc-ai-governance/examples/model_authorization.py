"""End-to-end example: five governance nodes vote to authorize a medical AI model.

Alice proposes `AUTHORIZE_MODEL` for `did:pqaid:medical-ai-v2`. Alice, Bob,
Carol and Dave approve. Eve abstains. The round finalises, the ML-DSA
signature on the result verifies, and an ``AuthorizationChain`` is populated
with the passed grant.
"""

from __future__ import annotations

from quantumshield.identity.agent import AgentIdentity

from pqc_ai_governance import (
    AuthorizationChain,
    AuthorizationGrant,
    ConsensusRound,
    GovernanceAuditLog,
    GovernanceNode,
    GovernanceProposal,
    NodeRegistry,
    ProposalKind,
    QuorumPolicy,
    VoteDecision,
)


def main() -> None:
    print("== PQC AI Governance: Model Authorization ==\n")

    # 1. Five governance nodes with varied weights.
    alice = GovernanceNode(identity=AgentIdentity.create("alice"), name="alice", weight=1)
    bob = GovernanceNode(identity=AgentIdentity.create("bob"), name="bob", weight=1)
    carol = GovernanceNode(identity=AgentIdentity.create("carol"), name="carol", weight=1)
    dave = GovernanceNode(identity=AgentIdentity.create("dave"), name="dave", weight=2)
    eve = GovernanceNode(identity=AgentIdentity.create("eve"), name="eve", weight=1)

    registry = NodeRegistry()
    for node in (alice, bob, carol, dave, eve):
        registry.register(node)
    print(f"Registered {len(registry)} nodes, total voting weight = {registry.total_weight()}")

    audit = GovernanceAuditLog()

    # 2. Alice proposes authorizing the medical AI model.
    proposal = GovernanceProposal.create(
        kind=ProposalKind.AUTHORIZE_MODEL,
        subject_id="did:pqaid:medical-ai-v2",
        title="Authorize medical-ai-v2 for production",
        description="Radiology triage model; HIPAA envelope in place.",
        proposer_did=alice.did,
        parameters={"environment": "prod", "max_rate_qps": 50, "region": "us-east-1"},
    )
    alice.sign_proposal(proposal)
    audit.log_proposal_created(proposal)
    assert GovernanceNode.verify_proposal(proposal), "proposer signature invalid"
    print(f"\nProposal {proposal.proposal_id}")
    print(f"  kind   : {proposal.kind.value}")
    print(f"  subject: {proposal.subject_id}")
    print(f"  hash   : {proposal.proposal_hash()[:16]}...")

    # 3. Cast votes: 4 approve, 1 abstain.
    rnd = ConsensusRound(proposal=proposal, registry=registry, policy=QuorumPolicy())
    votes = [
        (alice, VoteDecision.APPROVE, "clinical team approved"),
        (bob, VoteDecision.APPROVE, "security review clean"),
        (carol, VoteDecision.APPROVE, "compliance signed off"),
        (dave, VoteDecision.APPROVE, "infra capacity available"),
        (eve, VoteDecision.ABSTAIN, "not in my domain"),
    ]
    for voter, decision, rationale in votes:
        signed = voter.cast_vote(proposal, decision, rationale=rationale)
        rnd.cast(signed)
        audit.log_vote_cast(signed)
        print(f"  {voter.name:5s} -> {decision.value:<8s} ({rationale})")

    # 4. Finalize and sign the consensus result.
    result = rnd.finalize(coordinator=alice)
    audit.log_consensus_reached(result)
    print("\nConsensus:")
    print(f"  decision : {result.decision}")
    print(f"  reason   : {result.reason}")
    print(f"  approve  : {result.approve_weight}/{result.total_weight}")
    print(f"  reject   : {result.reject_weight}")
    print(f"  abstain  : {result.abstain_weight}")
    print(f"  signed by: {result.signer_did[:22]}... ({result.algorithm})")

    # 5. Verify the signed result, then bind it into an authorization chain.
    assert ConsensusRound.verify_result(result), "result signature failed to verify"
    print("  signature: OK (ML-DSA verified)")

    chain = AuthorizationChain(subject_id=proposal.subject_id)
    chain.add(
        AuthorizationGrant(
            subject_id=proposal.subject_id,
            kind=proposal.kind,
            result=result,
            scope=dict(proposal.parameters),
        )
    )
    audit.log_authorization_granted(
        subject_id=proposal.subject_id,
        kind=proposal.kind,
        proposal_id=proposal.proposal_id,
    )

    authorized = chain.is_authorized(ProposalKind.AUTHORIZE_MODEL)
    print(f"\nAuthorizationChain: is_authorized(AUTHORIZE_MODEL) = {authorized}")
    print(f"Audit entries: {len(audit)}")


if __name__ == "__main__":
    main()
