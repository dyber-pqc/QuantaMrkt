"""Votes and signed votes."""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class VoteDecision(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"
    ABSTAIN = "abstain"


@dataclass
class Vote:
    """A node's vote on a proposal (unsigned)."""

    vote_id: str
    proposal_id: str
    proposal_hash: str                    # binds the vote to a specific proposal hash
    voter_did: str
    decision: VoteDecision
    rationale: str = ""
    cast_at: str = ""

    @classmethod
    def create(
        cls,
        proposal_id: str,
        proposal_hash: str,
        voter_did: str,
        decision: VoteDecision,
        rationale: str = "",
    ) -> Vote:
        return cls(
            vote_id=f"urn:pqc-gov-vote:{uuid.uuid4().hex}",
            proposal_id=proposal_id,
            proposal_hash=proposal_hash,
            voter_did=voter_did,
            decision=decision,
            rationale=rationale,
            cast_at=datetime.now(timezone.utc).isoformat(),
        )

    def canonical_bytes(self) -> bytes:
        payload = {
            "vote_id": self.vote_id,
            "proposal_id": self.proposal_id,
            "proposal_hash": self.proposal_hash,
            "voter_did": self.voter_did,
            "decision": self.decision.value,
            "rationale": self.rationale,
            "cast_at": self.cast_at,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["decision"] = self.decision.value
        return d


@dataclass
class SignedVote:
    """A Vote + ML-DSA signature envelope."""

    vote: Vote
    algorithm: str
    signature: str                        # hex
    public_key: str                       # hex

    def to_dict(self) -> dict[str, Any]:
        return {
            "vote": self.vote.to_dict(),
            "algorithm": self.algorithm,
            "signature": self.signature,
            "public_key": self.public_key,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SignedVote:
        v = data["vote"]
        return cls(
            vote=Vote(
                vote_id=v["vote_id"],
                proposal_id=v["proposal_id"],
                proposal_hash=v["proposal_hash"],
                voter_did=v["voter_did"],
                decision=VoteDecision(v["decision"]),
                rationale=v.get("rationale", ""),
                cast_at=v.get("cast_at", ""),
            ),
            algorithm=data["algorithm"],
            signature=data["signature"],
            public_key=data["public_key"],
        )
