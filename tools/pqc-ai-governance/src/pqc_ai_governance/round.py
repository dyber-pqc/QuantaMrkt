"""ConsensusRound - one voting round with quorum policy and ML-DSA signed result."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.signatures import sign, verify

from pqc_ai_governance.errors import ProposalExpiredError
from pqc_ai_governance.node import NodeRegistry
from pqc_ai_governance.proposal import GovernanceProposal, ProposalStatus
from pqc_ai_governance.tally import VoteTally
from pqc_ai_governance.vote import SignedVote

if TYPE_CHECKING:
    from pqc_ai_governance.node import GovernanceNode


@dataclass
class QuorumPolicy:
    """Quorum / approval thresholds as fractions of total_weight.

    Default is PBFT-style: 2/3 of weight must participate AND 2/3 of cast
    (non-abstain) weight must approve.
    """

    min_participation_fraction: float = 2 / 3
    min_approval_fraction: float = 2 / 3

    def check(self, tally: VoteTally, total_weight: int) -> tuple[bool, str]:
        participation = tally.total_cast_weight()
        if total_weight == 0:
            return False, "total weight is zero"
        if participation / total_weight < self.min_participation_fraction:
            return False, (
                f"participation {participation}/{total_weight} "
                f"< {self.min_participation_fraction:.2%}"
            )
        effective = tally.approve_weight + tally.reject_weight   # abstain not counted in ratio
        if effective == 0:
            return False, "all votes are abstain"
        if tally.approve_weight / effective < self.min_approval_fraction:
            return False, (
                f"approval {tally.approve_weight}/{effective} "
                f"< {self.min_approval_fraction:.2%}"
            )
        return True, "quorum met, supermajority approve"


@dataclass
class ConsensusResult:
    """Signed outcome of a consensus round."""

    proposal_id: str
    proposal_hash: str
    decision: str                           # "passed" | "rejected"
    reason: str
    approve_weight: int
    reject_weight: int
    abstain_weight: int
    total_weight: int
    included_vote_ids: list[str] = field(default_factory=list)
    decided_at: str = ""
    signer_did: str = ""
    algorithm: str = ""
    signature: str = ""
    public_key: str = ""

    def canonical_bytes(self) -> bytes:
        payload = {
            "proposal_id": self.proposal_id,
            "proposal_hash": self.proposal_hash,
            "decision": self.decision,
            "reason": self.reason,
            "approve_weight": self.approve_weight,
            "reject_weight": self.reject_weight,
            "abstain_weight": self.abstain_weight,
            "total_weight": self.total_weight,
            "included_vote_ids": sorted(self.included_vote_ids),
            "decided_at": self.decided_at,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class ConsensusRound:
    """A consensus round: one proposal, many votes, deterministic signed result."""

    proposal: GovernanceProposal
    registry: NodeRegistry
    policy: QuorumPolicy = field(default_factory=QuorumPolicy)
    tally: VoteTally = field(init=False)

    def __post_init__(self) -> None:
        self.tally = VoteTally(proposal=self.proposal, registry=self.registry)

    def cast(self, signed_vote: SignedVote) -> None:
        if self.proposal.is_expired():
            raise ProposalExpiredError(
                f"proposal {self.proposal.proposal_id} is expired"
            )
        self.tally.add(signed_vote)

    def finalize(self, coordinator: GovernanceNode) -> ConsensusResult:
        """Decide, then sign the result with the coordinator's identity."""
        total_weight = self.registry.total_weight()
        ok, reason = self.policy.check(self.tally, total_weight)
        decision = "passed" if ok else "rejected"
        if ok:
            self.proposal.status = ProposalStatus.PASSED
        else:
            self.proposal.status = ProposalStatus.REJECTED

        result = ConsensusResult(
            proposal_id=self.proposal.proposal_id,
            proposal_hash=self.proposal.proposal_hash(),
            decision=decision,
            reason=reason,
            approve_weight=self.tally.approve_weight,
            reject_weight=self.tally.reject_weight,
            abstain_weight=self.tally.abstain_weight,
            total_weight=total_weight,
            included_vote_ids=[v.vote.vote_id for v in self.tally.valid_votes],
            decided_at=datetime.now(timezone.utc).isoformat(),
        )

        digest = hashlib.sha3_256(result.canonical_bytes()).digest()
        sig = sign(digest, coordinator.identity.signing_keypair)
        result.signer_did = coordinator.identity.did
        result.algorithm = coordinator.identity.signing_keypair.algorithm.value
        result.signature = sig.hex()
        result.public_key = coordinator.identity.signing_keypair.public_key.hex()
        return result

    @staticmethod
    def verify_result(result: ConsensusResult) -> bool:
        if not result.signature:
            return False
        try:
            algorithm = SignatureAlgorithm(result.algorithm)
        except ValueError:
            return False
        digest = hashlib.sha3_256(result.canonical_bytes()).digest()
        try:
            return verify(
                digest,
                bytes.fromhex(result.signature),
                bytes.fromhex(result.public_key),
                algorithm,
            )
        except Exception:
            return False
