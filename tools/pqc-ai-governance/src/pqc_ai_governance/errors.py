"""Exception hierarchy for pqc-ai-governance."""

from __future__ import annotations


class GovernanceError(Exception):
    """Base exception for all pqc-ai-governance errors."""


class InvalidProposalError(GovernanceError):
    """Raised when a governance proposal is structurally invalid or fails signature verification."""


class InvalidVoteError(GovernanceError):
    """Raised when a vote is structurally invalid or its signature fails to verify."""


class InsufficientQuorumError(GovernanceError):
    """Raised when the participation threshold for a consensus round is not met."""


class ConsensusFailedError(GovernanceError):
    """Raised when a consensus round cannot reach a decision."""


class UnknownNodeError(GovernanceError):
    """Raised when a referenced node DID is not present in the NodeRegistry."""


class ByzantineDetectedError(GovernanceError):
    """Raised when a node exhibits Byzantine behaviour (e.g., double-voting with conflicting decisions)."""


class ProposalExpiredError(GovernanceError):
    """Raised when a vote is cast on a proposal whose TTL has already elapsed."""
