"""Append-only audit log for governance operations."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from pqc_ai_governance.proposal import GovernanceProposal, ProposalKind
from pqc_ai_governance.round import ConsensusResult
from pqc_ai_governance.vote import SignedVote


# Operation name constants (stable strings written to the audit trail).
OP_PROPOSAL_CREATED = "proposal_created"
OP_VOTE_CAST = "vote_cast"
OP_CONSENSUS_REACHED = "consensus_reached"
OP_BYZANTINE_DETECTED = "byzantine_detected"
OP_NODE_ADDED = "node_added"
OP_NODE_REMOVED = "node_removed"
OP_AUTHORIZATION_GRANTED = "authorization_granted"
OP_AUTHORIZATION_REVOKED = "authorization_revoked"


@dataclass
class GovernanceAuditEntry:
    """A single governance event logged for audit."""

    timestamp: str
    operation: str
    proposal_id: str | None = None
    subject_id: str | None = None
    kind: str | None = None
    actor_did: str | None = None
    decision: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class GovernanceAuditLog:
    """Append-only audit log for governance operations.

    Production usage: persist entries to a real log backend. This class gives
    you an in-memory structure with filtering and JSON export for integrations.
    """

    def __init__(self, max_entries: int = 100_000) -> None:
        self._entries: list[GovernanceAuditEntry] = []
        self._max = max_entries

    def log(self, entry: GovernanceAuditEntry) -> None:
        if len(self._entries) >= self._max:
            self._entries.pop(0)
        self._entries.append(entry)

    # -- convenience helpers -----------------------------------------------

    def log_proposal_created(self, proposal: GovernanceProposal) -> None:
        self.log(
            GovernanceAuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                operation=OP_PROPOSAL_CREATED,
                proposal_id=proposal.proposal_id,
                subject_id=proposal.subject_id,
                kind=proposal.kind.value,
                actor_did=proposal.proposer_did,
                details={"title": proposal.title},
            )
        )

    def log_vote_cast(self, signed: SignedVote) -> None:
        self.log(
            GovernanceAuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                operation=OP_VOTE_CAST,
                proposal_id=signed.vote.proposal_id,
                actor_did=signed.vote.voter_did,
                decision=signed.vote.decision.value,
                details={"vote_id": signed.vote.vote_id},
            )
        )

    def log_consensus_reached(self, result: ConsensusResult) -> None:
        self.log(
            GovernanceAuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                operation=OP_CONSENSUS_REACHED,
                proposal_id=result.proposal_id,
                actor_did=result.signer_did,
                decision=result.decision,
                details={
                    "reason": result.reason,
                    "approve_weight": result.approve_weight,
                    "reject_weight": result.reject_weight,
                    "abstain_weight": result.abstain_weight,
                    "total_weight": result.total_weight,
                    "vote_count": len(result.included_vote_ids),
                },
            )
        )

    def log_byzantine_detected(
        self, voter_did: str, proposal_id: str, prior: str, now: str
    ) -> None:
        self.log(
            GovernanceAuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                operation=OP_BYZANTINE_DETECTED,
                proposal_id=proposal_id,
                actor_did=voter_did,
                details={"prior_decision": prior, "conflicting_decision": now},
            )
        )

    def log_node_added(self, did: str, name: str, weight: int) -> None:
        self.log(
            GovernanceAuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                operation=OP_NODE_ADDED,
                actor_did=did,
                details={"name": name, "weight": weight},
            )
        )

    def log_node_removed(self, did: str) -> None:
        self.log(
            GovernanceAuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                operation=OP_NODE_REMOVED,
                actor_did=did,
            )
        )

    def log_authorization_granted(
        self, subject_id: str, kind: ProposalKind, proposal_id: str
    ) -> None:
        self.log(
            GovernanceAuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                operation=OP_AUTHORIZATION_GRANTED,
                proposal_id=proposal_id,
                subject_id=subject_id,
                kind=kind.value,
            )
        )

    def log_authorization_revoked(
        self, subject_id: str, kind: ProposalKind, proposal_id: str
    ) -> None:
        self.log(
            GovernanceAuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                operation=OP_AUTHORIZATION_REVOKED,
                proposal_id=proposal_id,
                subject_id=subject_id,
                kind=kind.value,
            )
        )

    # -- query / export ----------------------------------------------------

    def entries(
        self,
        limit: int = 100,
        operation: str | None = None,
        proposal_id: str | None = None,
        actor_did: str | None = None,
    ) -> list[GovernanceAuditEntry]:
        filtered = self._entries
        if operation:
            filtered = [e for e in filtered if e.operation == operation]
        if proposal_id:
            filtered = [e for e in filtered if e.proposal_id == proposal_id]
        if actor_did:
            filtered = [e for e in filtered if e.actor_did == actor_did]
        return filtered[-limit:][::-1]

    def export_json(self) -> str:
        return json.dumps([e.to_dict() for e in self._entries], indent=2)

    def clear(self) -> None:
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)
