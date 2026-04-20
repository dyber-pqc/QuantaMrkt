"""Signing and verification for ContentManifests."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.signatures import sign, verify
from quantumshield.identity.agent import AgentIdentity

from pqc_content_provenance.errors import ContentHashMismatchError
from pqc_content_provenance.manifest import ContentManifest


@dataclass(frozen=True)
class VerificationResult:
    """Result of verifying a ContentManifest against its content."""

    valid: bool
    manifest_id: str
    signer_did: str | None
    algorithm: str | None
    content_hash_match: bool
    signature_match: bool
    error: str | None = None


class ManifestSigner:
    """Signs ContentManifests with an AgentIdentity (usually the model's identity).

    Usage:
        identity = AgentIdentity.create("llama-3-8b-signer")
        signer = ManifestSigner(identity)
        content = b"Hello, this is AI-generated text."
        manifest = ContentManifest.create(content, "text/plain", attribution, ctx)
        signed = signer.sign(manifest)
    """

    def __init__(self, identity: AgentIdentity):
        self.identity = identity

    def sign(self, manifest: ContentManifest) -> ContentManifest:
        """Sign the manifest in place and return it."""
        canonical = manifest.canonical_bytes()
        # Sign the SHA3-256 digest of the canonical bytes (deterministic)
        digest = hashlib.sha3_256(canonical).digest()
        signature = sign(digest, self.identity.signing_keypair)
        manifest.signer_did = self.identity.did
        manifest.algorithm = self.identity.signing_keypair.algorithm.value
        manifest.signature = signature.hex()
        manifest.public_key = self.identity.signing_keypair.public_key.hex()
        manifest.signed_at = datetime.now(timezone.utc).isoformat()
        return manifest

    @staticmethod
    def verify(manifest: ContentManifest, content: bytes | None = None) -> VerificationResult:
        """Verify the manifest signature and (optionally) the content hash."""
        content_hash_match = True
        if content is not None:
            expected = hashlib.sha3_256(content).hexdigest()
            content_hash_match = expected == manifest.content_hash

        try:
            algorithm = SignatureAlgorithm(manifest.algorithm)
        except ValueError:
            return VerificationResult(
                valid=False,
                manifest_id=manifest.manifest_id,
                signer_did=manifest.signer_did,
                algorithm=manifest.algorithm,
                content_hash_match=content_hash_match,
                signature_match=False,
                error=f"unknown algorithm {manifest.algorithm}",
            )

        canonical = manifest.canonical_bytes()
        digest = hashlib.sha3_256(canonical).digest()

        try:
            sig_valid = verify(
                digest,
                bytes.fromhex(manifest.signature),
                bytes.fromhex(manifest.public_key),
                algorithm,
            )
        except Exception as exc:
            return VerificationResult(
                valid=False,
                manifest_id=manifest.manifest_id,
                signer_did=manifest.signer_did,
                algorithm=manifest.algorithm,
                content_hash_match=content_hash_match,
                signature_match=False,
                error=f"signature verify failed: {exc}",
            )

        all_ok = sig_valid and content_hash_match
        err = None
        if not sig_valid:
            err = "invalid ML-DSA signature"
        elif not content_hash_match:
            err = "content hash does not match manifest"

        return VerificationResult(
            valid=all_ok,
            manifest_id=manifest.manifest_id,
            signer_did=manifest.signer_did,
            algorithm=manifest.algorithm,
            content_hash_match=content_hash_match,
            signature_match=sig_valid,
            error=err,
        )

    def sign_and_raise_on_mismatch(
        self, manifest: ContentManifest, content: bytes
    ) -> ContentManifest:
        """Sign and then double-check the content hash matches (defensive signing)."""
        computed = ContentManifest.compute_content_hash(content)
        if computed != manifest.content_hash:
            raise ContentHashMismatchError(
                f"content hash in manifest ({manifest.content_hash[:16]}...) "
                f"does not match actual content ({computed[:16]}...)"
            )
        return self.sign(manifest)
