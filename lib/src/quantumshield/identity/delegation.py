"""Delegation chains for agent-to-agent capability delegation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Delegation:
    """A single delegation entry in a chain."""

    delegator_did: str
    delegate_did: str
    scope: str
    expires_at: datetime
    signature: bytes


@dataclass
class DelegationChain:
    """A chain of delegations from one agent to another.

    Delegation chains allow an agent to grant a subset of its capabilities
    to another agent, with cryptographic attestation at each step.
    """

    delegations: list[Delegation] = field(default_factory=list)

    def add(self, delegation: Delegation) -> None:
        """Add a delegation entry to the chain."""
        self.delegations.append(delegation)

    def verify_chain(self) -> bool:
        """Verify the entire delegation chain is valid.

        Checks that:
        - Each delegation's signature is valid
        - Each delegator matches the previous delegate
        - No delegation has expired

        Returns:
            True if the chain is valid, False otherwise.

        .. note::
            Stub implementation. TODO: Implement full cryptographic chain verification.
        """
        if not self.delegations:
            return False

        now = datetime.now(timezone.utc)

        # Check that chain links are connected
        for i in range(1, len(self.delegations)):
            prev = self.delegations[i - 1]
            curr = self.delegations[i]
            if prev.delegate_did != curr.delegator_did:
                return False

        # Check expiry
        for delegation in self.delegations:
            if delegation.expires_at < now:
                return False

        # TODO: Verify each signature cryptographically
        return True
