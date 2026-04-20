"""Governance proposals - the thing nodes vote on."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any


class ProposalKind(str, Enum):
    """Types of things enterprise AI governance votes on."""

    AUTHORIZE_MODEL = "authorize-model"             # grant model permission to run
    REVOKE_MODEL = "revoke-model"
    AUTHORIZE_AGENT = "authorize-agent"             # grant agent permission to act
    REVOKE_AGENT = "revoke-agent"
    UPDATE_POLICY = "update-policy"                 # change a runtime policy
    ADD_NODE = "add-node"                           # admit a new governance node
    REMOVE_NODE = "remove-node"
    EMERGENCY_FREEZE = "emergency-freeze"           # halt all agent action
    DELEGATION = "delegation"                       # allow agent X to delegate to Y


class ProposalStatus(str, Enum):
    OPEN = "open"
    PASSED = "passed"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class GovernanceProposal:
    """A proposal nodes vote on.

    The ``subject_id`` identifies what the proposal is about (model DID, agent DID,
    policy id, etc.). ``parameters`` is an arbitrary dict of rule-specific fields.
    """

    proposal_id: str
    kind: ProposalKind
    subject_id: str                       # e.g. "did:pqaid:..." for model/agent
    title: str
    description: str
    proposer_did: str
    parameters: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    expires_at: str = ""
    status: ProposalStatus = ProposalStatus.OPEN

    # Populated by proposer signature
    signer_did: str = ""
    algorithm: str = ""
    signature: str = ""                   # hex
    public_key: str = ""                  # hex

    @classmethod
    def create(
        cls,
        kind: ProposalKind,
        subject_id: str,
        title: str,
        proposer_did: str,
        description: str = "",
        parameters: dict[str, Any] | None = None,
        ttl_seconds: int = 86400,
    ) -> GovernanceProposal:
        now = datetime.now(timezone.utc)
        return cls(
            proposal_id=f"urn:pqc-gov-prop:{uuid.uuid4().hex}",
            kind=kind,
            subject_id=subject_id,
            title=title,
            description=description,
            proposer_did=proposer_did,
            parameters=dict(parameters or {}),
            created_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=ttl_seconds)).isoformat(),
            status=ProposalStatus.OPEN,
        )

    def canonical_bytes(self) -> bytes:
        """Bytes covered by the proposer's signature."""
        payload = {
            "proposal_id": self.proposal_id,
            "kind": self.kind.value,
            "subject_id": self.subject_id,
            "title": self.title,
            "description": self.description,
            "proposer_did": self.proposer_did,
            "parameters": self.parameters,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def proposal_hash(self) -> str:
        return hashlib.sha3_256(self.canonical_bytes()).hexdigest()

    def is_expired(self) -> bool:
        try:
            exp = datetime.fromisoformat(self.expires_at)
            return datetime.now(timezone.utc) > exp
        except ValueError:
            return False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["kind"] = self.kind.value
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GovernanceProposal:
        return cls(
            proposal_id=data["proposal_id"],
            kind=ProposalKind(data["kind"]),
            subject_id=data["subject_id"],
            title=data["title"],
            description=data.get("description", ""),
            proposer_did=data["proposer_did"],
            parameters=dict(data.get("parameters", {})),
            created_at=data.get("created_at", ""),
            expires_at=data.get("expires_at", ""),
            status=ProposalStatus(data.get("status", "open")),
            signer_did=data.get("signer_did", ""),
            algorithm=data.get("algorithm", ""),
            signature=data.get("signature", ""),
            public_key=data.get("public_key", ""),
        )
