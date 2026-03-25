"""Stub for PQC signing operations."""

from __future__ import annotations

from typing import Any


class SigningService:
    """Handles manifest signing and verification using post-quantum algorithms."""

    def sign_manifest(self, manifest: dict[str, Any], key_id: str) -> dict[str, Any]:
        """Sign a model manifest with the specified key.

        TODO: Integrate with PQC key store (ML-DSA-65 / SLH-DSA).
        TODO: Produce detached signature and attach to manifest.signatures[].
        TODO: Support hardware-backed keys via PKCS#11.
        """
        raise NotImplementedError("SigningService.sign_manifest is not yet implemented")

    def verify_manifest(self, manifest: dict[str, Any]) -> bool:
        """Verify all signatures attached to a manifest.

        TODO: Resolve public keys from DID documents.
        TODO: Validate each SignatureEntry against the manifest content.
        TODO: Support hybrid (classical + PQC) signature verification.
        """
        raise NotImplementedError("SigningService.verify_manifest is not yet implemented")
