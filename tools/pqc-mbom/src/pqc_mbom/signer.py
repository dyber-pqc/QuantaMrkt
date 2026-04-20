"""MBOM signing and verification using ML-DSA."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.signatures import sign, verify
from quantumshield.identity.agent import AgentIdentity

from pqc_mbom.errors import SignatureVerificationError
from pqc_mbom.mbom import MBOM


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of verifying a signed MBOM."""

    signature_valid: bool
    root_hash_valid: bool
    mbom_id: str
    signer_did: str | None
    algorithm: str | None
    error: str | None = None

    @property
    def valid(self) -> bool:
        """True iff both the ML-DSA signature and the recomputed root match."""
        return self.signature_valid and self.root_hash_valid


class MBOMSigner:
    """Signs MBOM documents with a fixed AgentIdentity.

    Usage:
        identity = AgentIdentity.create("llama-release-pipeline")
        signer = MBOMSigner(identity)
        signer.sign(mbom)   # mutates mbom in place
    """

    def __init__(self, identity: AgentIdentity) -> None:
        self.identity = identity

    def sign(self, mbom: MBOM) -> MBOM:
        """Populate signature fields on `mbom` using ML-DSA.

        Recomputes the components_root_hash before signing so the signature
        always commits to the current component set.
        """
        mbom.recompute_root()
        digest = hashlib.sha3_256(mbom.canonical_bytes()).digest()
        sig = sign(digest, self.identity.signing_keypair)
        mbom.signer_did = self.identity.did
        mbom.algorithm = self.identity.signing_keypair.algorithm.value
        mbom.signature = sig.hex()
        mbom.public_key = self.identity.signing_keypair.public_key.hex()
        mbom.signed_at = datetime.now(timezone.utc).isoformat()
        return mbom


class MBOMVerifier:
    """Verifies MBOM signatures and component-root integrity."""

    @staticmethod
    def verify(mbom: MBOM) -> VerificationResult:
        """Check both the signature and the components_root_hash."""
        expected_root = MBOMVerifier._expected_root(mbom)
        root_ok = expected_root == mbom.components_root_hash

        if not mbom.signature or not mbom.algorithm:
            return VerificationResult(
                signature_valid=False,
                root_hash_valid=root_ok,
                mbom_id=mbom.mbom_id,
                signer_did=mbom.signer_did or None,
                algorithm=mbom.algorithm or None,
                error="mbom is unsigned",
            )

        try:
            algorithm = SignatureAlgorithm(mbom.algorithm)
        except ValueError:
            return VerificationResult(
                signature_valid=False,
                root_hash_valid=root_ok,
                mbom_id=mbom.mbom_id,
                signer_did=mbom.signer_did,
                algorithm=mbom.algorithm,
                error=f"unknown algorithm {mbom.algorithm}",
            )

        digest = hashlib.sha3_256(mbom.canonical_bytes()).digest()
        try:
            sig_valid = verify(
                digest,
                bytes.fromhex(mbom.signature),
                bytes.fromhex(mbom.public_key),
                algorithm,
            )
        except Exception as exc:
            return VerificationResult(
                signature_valid=False,
                root_hash_valid=root_ok,
                mbom_id=mbom.mbom_id,
                signer_did=mbom.signer_did,
                algorithm=mbom.algorithm,
                error=f"signature verify failed: {exc}",
            )

        if not sig_valid:
            return VerificationResult(
                signature_valid=False,
                root_hash_valid=root_ok,
                mbom_id=mbom.mbom_id,
                signer_did=mbom.signer_did,
                algorithm=mbom.algorithm,
                error="invalid ML-DSA signature",
            )

        if not root_ok:
            return VerificationResult(
                signature_valid=True,
                root_hash_valid=False,
                mbom_id=mbom.mbom_id,
                signer_did=mbom.signer_did,
                algorithm=mbom.algorithm,
                error=(
                    f"components_root_hash mismatch (expected {expected_root[:16]}, "
                    f"got {mbom.components_root_hash[:16]})"
                ),
            )

        return VerificationResult(
            signature_valid=True,
            root_hash_valid=True,
            mbom_id=mbom.mbom_id,
            signer_did=mbom.signer_did,
            algorithm=mbom.algorithm,
        )

    @staticmethod
    def verify_or_raise(mbom: MBOM) -> VerificationResult:
        """Verify and raise SignatureVerificationError on any failure."""
        result = MBOMVerifier.verify(mbom)
        if not result.valid:
            raise SignatureVerificationError(
                f"MBOM {mbom.mbom_id} failed verification: {result.error}"
            )
        return result

    @staticmethod
    def _expected_root(mbom: MBOM) -> str:
        component_hashes = sorted(c.hash() for c in mbom.components)
        concat = "|".join(component_hashes).encode("utf-8")
        return hashlib.sha3_256(concat).hexdigest()
