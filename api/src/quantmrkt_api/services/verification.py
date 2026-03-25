"""Stub for identity and model verification."""

from __future__ import annotations


class VerificationService:
    """Verifies agent identities and model integrity."""

    def verify_agent(self, agent_did: str) -> dict:
        """Verify an agent's DID document and key material.

        TODO: Resolve DID document from did:web endpoint.
        TODO: Validate PQC public key is well-formed.
        TODO: Check revocation status against on-chain registry.
        """
        raise NotImplementedError("VerificationService.verify_agent is not yet implemented")

    def verify_model(self, namespace: str) -> dict:
        """Verify model integrity: file hashes, signatures, and provenance.

        TODO: Fetch manifest from registry storage.
        TODO: Re-hash files and compare against manifest.files[].sha256.
        TODO: Verify all manifest.signatures[] entries.
        TODO: Validate SLSA provenance chain.
        """
        raise NotImplementedError("VerificationService.verify_model is not yet implemented")
