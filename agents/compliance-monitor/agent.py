"""Compliance Monitor -- watches governance proposals and emits audit events."""

from __future__ import annotations

import json
from pathlib import Path

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.identity.agent import AgentIdentity

from pqc_ai_governance import (
    GovernanceAuditEntry,
    GovernanceAuditLog,
    GovernanceProposal,
    ProposalKind,
)
from pqc_audit_log_fs import InferenceEvent, LogAppender, RotationPolicy


IDENTITY_FILE = Path(__file__).parent / "identity.json"


def load_identity() -> AgentIdentity:
    data = json.loads(IDENTITY_FILE.read_text())
    return AgentIdentity.create(
        data["name"],
        capabilities=data["capabilities"],
        algorithm=SignatureAlgorithm.ML_DSA_87,
    )


def evaluate(agent: AgentIdentity, proposal: GovernanceProposal) -> tuple[str, GovernanceAuditLog]:
    """Emergency-freeze proposals are always flagged."""
    gov_log = GovernanceAuditLog()
    verdict = "alert" if proposal.kind is ProposalKind.EMERGENCY_FREEZE else "ok"
    gov_log.log(GovernanceAuditEntry(
        timestamp=proposal.created_at,
        operation="proposal_reviewed",
        proposal_id=proposal.proposal_id,
        subject_id=proposal.subject_id,
        kind=proposal.kind.value,
        actor_did=agent.did,
        decision=verdict,
    ))
    return verdict, gov_log


def main() -> None:
    agent = load_identity()
    print(f"[agent] {agent.did}")

    proposal = GovernanceProposal.create(
        kind=ProposalKind.EMERGENCY_FREEZE,
        subject_id="did:pqaid:legacy-monitor",
        title="Freeze legacy-monitor agent",
        proposer_did="did:example:compliance-team",
        description="ML-DSA-44 agent scheduled for decommission.",
    )
    verdict, _ = evaluate(agent, proposal)
    print(f"[governance] verdict={verdict} proposal={proposal.proposal_id}")

    log_dir = Path(__file__).parent / "audit-log"
    with LogAppender(
        str(log_dir), agent, rotation=RotationPolicy(max_events_per_segment=100)
    ) as log:
        log.append(InferenceEvent.create(
            model_did=agent.did,
            model_version="1.0",
            input_bytes=proposal.proposal_id.encode(),
            output_bytes=verdict.encode(),
            decision_type="compliance-review",
            decision_label=verdict,
            actor_did="did:example:compliance-team",
            metadata={"kind": proposal.kind.value},
        ))
    print(f"[audit] segment sealed at {log_dir}")


if __name__ == "__main__":
    main()
