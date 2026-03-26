"""Message signing and verification for PQC MCP Transport."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.signatures import sign, verify
from quantumshield.identity.agent import AgentIdentity


@dataclass
class VerificationResult:
    """Result of verifying a PQC-signed MCP message."""

    valid: bool
    signer_did: str | None = None
    algorithm: str | None = None
    timestamp: str | None = None
    nonce: str | None = None
    error: str | None = None


class MessageSigner:
    """Signs and verifies MCP JSON-RPC messages using ML-DSA post-quantum signatures."""

    def __init__(self, identity: AgentIdentity) -> None:
        self.identity = identity

    @staticmethod
    def canonicalize(message: dict) -> bytes:
        """Deterministic JSON serialization for signing.

        Removes the ``_pqc`` envelope if present, sorts keys, and uses
        compact separators so that the canonical form is reproducible
        regardless of insertion order or whitespace.
        """
        clean = {k: v for k, v in message.items() if k != "_pqc"}
        return json.dumps(clean, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign_message(self, message: dict) -> dict:
        """Add a ``_pqc`` envelope with an ML-DSA signature to *message*.

        Returns a new dict (the original is not mutated).
        """
        canonical = self.canonicalize(message)
        msg_hash = hashlib.sha3_256(canonical).digest()
        signature = sign(msg_hash, self.identity.signing_keypair)
        nonce = os.urandom(16).hex()

        signed = dict(message)
        signed["_pqc"] = {
            "signer_did": self.identity.did,
            "algorithm": self.identity.signing_keypair.algorithm.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "nonce": nonce,
            "signature": signature.hex(),
            "public_key": self.identity.signing_keypair.public_key.hex(),
        }
        return signed

    @staticmethod
    def verify_message(message: dict) -> VerificationResult:
        """Verify the ``_pqc`` envelope on *message*.

        Returns a :class:`VerificationResult` whose ``.valid`` flag
        indicates whether the signature verified successfully.
        """
        pqc = message.get("_pqc")
        if not pqc:
            return VerificationResult(valid=False, error="No _pqc envelope")

        try:
            canonical = MessageSigner.canonicalize(message)
            msg_hash = hashlib.sha3_256(canonical).digest()
            sig_bytes = bytes.fromhex(pqc["signature"])
            pub_bytes = bytes.fromhex(pqc["public_key"])
            algorithm = SignatureAlgorithm(pqc["algorithm"])

            is_valid = verify(msg_hash, sig_bytes, pub_bytes, algorithm)
            return VerificationResult(
                valid=is_valid,
                signer_did=pqc.get("signer_did"),
                algorithm=pqc.get("algorithm"),
                timestamp=pqc.get("timestamp"),
                nonce=pqc.get("nonce"),
            )
        except Exception as exc:
            return VerificationResult(valid=False, error=str(exc))

    @staticmethod
    def strip_pqc(message: dict) -> dict:
        """Return a copy of *message* without the ``_pqc`` envelope."""
        return {k: v for k, v in message.items() if k != "_pqc"}
