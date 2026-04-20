"""Client-side signing and server-side verification of ClientUpdates."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.signatures import sign, verify
from quantumshield.identity.agent import AgentIdentity

from pqc_federated_learning.update import ClientUpdate


@dataclass(frozen=True)
class UpdateVerificationResult:
    valid: bool
    client_did: str | None
    round_id: str | None
    content_hash_ok: bool
    signature_ok: bool
    error: str | None = None


class UpdateSigner:
    """Signs ClientUpdates with an AgentIdentity (the client's identity)."""

    def __init__(self, identity: AgentIdentity):
        self.identity = identity

    def sign(self, update: ClientUpdate) -> ClientUpdate:
        canonical = update.canonical_bytes()
        digest = hashlib.sha3_256(canonical).digest()
        sig = sign(digest, self.identity.signing_keypair)
        update.signer_did = self.identity.did
        update.algorithm = self.identity.signing_keypair.algorithm.value
        update.signature = sig.hex()
        update.public_key = self.identity.signing_keypair.public_key.hex()
        update.signed_at = datetime.now(timezone.utc).isoformat()
        return update

    @staticmethod
    def verify(update: ClientUpdate) -> UpdateVerificationResult:
        # Recompute content hash
        expected_hash = ClientUpdate.compute_content_hash(
            update.metadata, update.tensors, update.created_at
        )
        content_hash_ok = expected_hash == update.content_hash

        if not update.signature or not update.algorithm or not update.public_key:
            return UpdateVerificationResult(
                valid=False,
                client_did=update.signer_did or None,
                round_id=update.metadata.round_id,
                content_hash_ok=content_hash_ok,
                signature_ok=False,
                error="missing signature fields",
            )

        try:
            algorithm = SignatureAlgorithm(update.algorithm)
        except ValueError:
            return UpdateVerificationResult(
                valid=False,
                client_did=update.signer_did,
                round_id=update.metadata.round_id,
                content_hash_ok=content_hash_ok,
                signature_ok=False,
                error=f"unknown algorithm {update.algorithm}",
            )

        digest = hashlib.sha3_256(update.canonical_bytes()).digest()
        try:
            sig_ok = verify(
                digest,
                bytes.fromhex(update.signature),
                bytes.fromhex(update.public_key),
                algorithm,
            )
        except Exception as exc:
            return UpdateVerificationResult(
                valid=False,
                client_did=update.signer_did,
                round_id=update.metadata.round_id,
                content_hash_ok=content_hash_ok,
                signature_ok=False,
                error=f"verify failed: {exc}",
            )

        err = None
        valid = sig_ok and content_hash_ok
        if not sig_ok:
            err = "invalid ML-DSA signature"
        elif not content_hash_ok:
            err = "content hash mismatch"

        return UpdateVerificationResult(
            valid=valid,
            client_did=update.signer_did,
            round_id=update.metadata.round_id,
            content_hash_ok=content_hash_ok,
            signature_ok=sig_ok,
            error=err,
        )
