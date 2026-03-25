"""Agent identity creation and management."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.keys import SigningKeypair, generate_signing_keypair
from quantumshield.core.signatures import sign
from quantumshield.identity.credentials import ActionCredential


@dataclass
class AgentIdentity:
    """A post-quantum cryptographic identity for an AI agent.

    Each agent has a unique DID (Decentralized Identifier) derived from its
    public signing key, along with a set of declared capabilities.
    """

    did: str
    name: str
    signing_keypair: SigningKeypair
    capabilities: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def create(
        cls,
        name: str,
        capabilities: list[str] | None = None,
        algorithm: SignatureAlgorithm = SignatureAlgorithm.ML_DSA_65,
    ) -> AgentIdentity:
        """Create a new agent identity with a fresh keypair.

        Args:
            name: Human-readable name for the agent.
            capabilities: List of capability strings (e.g., ["sign", "verify"]).
            algorithm: The signature algorithm to use. Defaults to ML-DSA-65.

        Returns:
            A new AgentIdentity with a generated DID.
        """
        keypair = generate_signing_keypair(algorithm)
        pk_hash = hashlib.sha3_256(keypair.public_key).hexdigest()
        did = f"did:pqaid:{pk_hash}"
        return cls(
            did=did,
            name=name,
            signing_keypair=keypair,
            capabilities=capabilities or [],
        )

    def sign_action(self, action: str, target: str) -> ActionCredential:
        """Sign an action credential attesting this agent performed an action.

        Args:
            action: The action performed (e.g., "model.sign", "code.analyze").
            target: The target of the action (e.g., a model path or file hash).

        Returns:
            A signed ActionCredential.
        """
        message = f"{self.did}:{action}:{target}".encode("utf-8")
        signature = sign(message, self.signing_keypair)
        return ActionCredential(
            signer_did=self.did,
            action=action,
            target=target,
            signed_at=datetime.now(timezone.utc),
            signature=signature,
            algorithm=self.signing_keypair.algorithm,
        )

    def export(self) -> str:
        """Export the public identity information as JSON.

        Returns:
            JSON string with DID, name, public key, capabilities, and creation time.
            Private key is NOT included.
        """
        data = {
            "did": self.did,
            "name": self.name,
            "public_key": self.signing_keypair.public_key.hex(),
            "algorithm": self.signing_keypair.algorithm.value,
            "capabilities": self.capabilities,
            "created_at": self.created_at.isoformat(),
        }
        return json.dumps(data, indent=2)

    @classmethod
    def import_full(cls, data: str) -> AgentIdentity:
        """Import a full agent identity from JSON (including private key).

        Args:
            data: JSON string containing full identity data with private key.

        Returns:
            A reconstructed AgentIdentity.
        """
        parsed = json.loads(data)
        algorithm = SignatureAlgorithm(parsed["algorithm"])
        keypair = SigningKeypair(
            public_key=bytes.fromhex(parsed["public_key"]),
            private_key=bytes.fromhex(parsed["private_key"]),
            algorithm=algorithm,
        )
        return cls(
            did=parsed["did"],
            name=parsed["name"],
            signing_keypair=keypair,
            capabilities=parsed.get("capabilities", []),
            created_at=datetime.fromisoformat(parsed["created_at"]),
        )
