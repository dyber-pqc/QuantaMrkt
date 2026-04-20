"""GovernanceNode - one voting participant in the consensus."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.signatures import sign, verify
from quantumshield.identity.agent import AgentIdentity

from pqc_ai_governance.errors import UnknownNodeError
from pqc_ai_governance.proposal import GovernanceProposal
from pqc_ai_governance.vote import SignedVote, Vote, VoteDecision


@dataclass
class GovernanceNode:
    """A voting node in the governance consensus.

    Wraps an ``AgentIdentity``; produces signed proposals and signed votes.
    ``weight`` of 1 gives a one-node-one-vote system; >1 yields weighted voting.
    """

    identity: AgentIdentity
    name: str
    weight: int = 1

    @property
    def did(self) -> str:
        return self.identity.did

    def sign_proposal(self, proposal: GovernanceProposal) -> GovernanceProposal:
        """Sign the proposal as the proposer."""
        digest = hashlib.sha3_256(proposal.canonical_bytes()).digest()
        sig = sign(digest, self.identity.signing_keypair)
        proposal.signer_did = self.identity.did
        proposal.algorithm = self.identity.signing_keypair.algorithm.value
        proposal.signature = sig.hex()
        proposal.public_key = self.identity.signing_keypair.public_key.hex()
        return proposal

    def cast_vote(
        self,
        proposal: GovernanceProposal,
        decision: VoteDecision,
        rationale: str = "",
    ) -> SignedVote:
        """Cast a signed vote on a proposal."""
        vote = Vote.create(
            proposal_id=proposal.proposal_id,
            proposal_hash=proposal.proposal_hash(),
            voter_did=self.identity.did,
            decision=decision,
            rationale=rationale,
        )
        digest = hashlib.sha3_256(vote.canonical_bytes()).digest()
        sig = sign(digest, self.identity.signing_keypair)
        return SignedVote(
            vote=vote,
            algorithm=self.identity.signing_keypair.algorithm.value,
            signature=sig.hex(),
            public_key=self.identity.signing_keypair.public_key.hex(),
        )

    @staticmethod
    def verify_vote(signed: SignedVote) -> bool:
        try:
            algorithm = SignatureAlgorithm(signed.algorithm)
        except ValueError:
            return False
        digest = hashlib.sha3_256(signed.vote.canonical_bytes()).digest()
        try:
            return verify(
                digest,
                bytes.fromhex(signed.signature),
                bytes.fromhex(signed.public_key),
                algorithm,
            )
        except Exception:
            return False

    @staticmethod
    def verify_proposal(proposal: GovernanceProposal) -> bool:
        if not proposal.signature:
            return False
        try:
            algorithm = SignatureAlgorithm(proposal.algorithm)
        except ValueError:
            return False
        digest = hashlib.sha3_256(proposal.canonical_bytes()).digest()
        try:
            return verify(
                digest,
                bytes.fromhex(proposal.signature),
                bytes.fromhex(proposal.public_key),
                algorithm,
            )
        except Exception:
            return False


@dataclass
class NodeRegistry:
    """Allow-list of governance nodes, keyed by DID."""

    nodes: dict[str, GovernanceNode] = field(default_factory=dict)

    def register(self, node: GovernanceNode) -> None:
        self.nodes[node.did] = node

    def remove(self, did: str) -> None:
        if did not in self.nodes:
            raise UnknownNodeError(f"no node with did {did}")
        del self.nodes[did]

    def get(self, did: str) -> GovernanceNode:
        if did not in self.nodes:
            raise UnknownNodeError(f"no node with did {did}")
        return self.nodes[did]

    def is_member(self, did: str) -> bool:
        return did in self.nodes

    def total_weight(self) -> int:
        return sum(n.weight for n in self.nodes.values())

    def list_dids(self) -> list[str]:
        return sorted(self.nodes.keys())

    def __len__(self) -> int:
        return len(self.nodes)
