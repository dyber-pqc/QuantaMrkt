"""AuthorizationChain - passed ConsensusResults that authorize an agent/model to act."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pqc_ai_governance.errors import GovernanceError
from pqc_ai_governance.proposal import ProposalKind
from pqc_ai_governance.round import ConsensusRound, ConsensusResult


# Map each AUTHORIZE_* kind to its canonical REVOKE_* counterpart.
_REVOKE_MAP: dict[ProposalKind, ProposalKind] = {
    ProposalKind.AUTHORIZE_MODEL: ProposalKind.REVOKE_MODEL,
    ProposalKind.AUTHORIZE_AGENT: ProposalKind.REVOKE_AGENT,
}


@dataclass
class AuthorizationGrant:
    """A passed proposal that confers authority on a subject (model DID or agent DID)."""

    subject_id: str
    kind: ProposalKind
    result: ConsensusResult
    scope: dict[str, Any] = field(default_factory=dict)

    def is_passed(self) -> bool:
        return self.result.decision == "passed"

    def verify(self) -> bool:
        """Verify the underlying ConsensusResult's ML-DSA signature."""
        return ConsensusRound.verify_result(self.result)


@dataclass
class AuthorizationChain:
    """Ordered set of ``AuthorizationGrant`` records referencing a single subject."""

    subject_id: str
    grants: list[AuthorizationGrant] = field(default_factory=list)

    def add(self, grant: AuthorizationGrant) -> None:
        if grant.subject_id != self.subject_id:
            raise GovernanceError(
                f"grant subject {grant.subject_id} != chain subject {self.subject_id}"
            )
        self.grants.append(grant)

    def is_authorized(self, kind: ProposalKind) -> bool:
        """Return True if there is at least one passed ``AUTHORIZE_*`` grant of
        this kind and no subsequent matching ``REVOKE_*``."""
        authorized = False
        revoke_kind = _REVOKE_MAP.get(kind)
        for grant in self.grants:
            if not grant.is_passed():
                continue
            if grant.kind == kind:
                authorized = True
            elif revoke_kind is not None and grant.kind == revoke_kind:
                authorized = False
        return authorized

    def __len__(self) -> int:
        return len(self.grants)
