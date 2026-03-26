"""Shield Registry client for pushing and pulling signed model manifests.

Uses httpx to talk to the quantamrkt.com API.  All requests that require
authentication read the token from ``~/.quantumshield/config.json``.
"""

from __future__ import annotations

from typing import Any

import httpx

from quantumshield.cli.config import get_api_url, get_auth_token
from quantumshield.registry.manifest import ModelManifest


class RegistryError(Exception):
    """Raised when a registry API call fails."""


class ShieldRegistry:
    """HTTP client for the QuantumShield model registry."""

    def __init__(self, api_url: str | None = None) -> None:
        self.api_url = (api_url or get_api_url()).rstrip("/")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _headers(self, auth: bool = True) -> dict[str, str]:
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": "quantumshield-cli/0.1.0",
        }
        if auth:
            token = get_auth_token()
            if token:
                headers["Authorization"] = f"Bearer {token}"
        return headers

    def _raise_for_status(self, resp: httpx.Response) -> None:
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("error", resp.text)
            except Exception:
                detail = resp.text
            raise RegistryError(
                f"Registry API error {resp.status_code}: {detail}"
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def push(self, manifest: ModelManifest, namespace: str) -> dict[str, Any]:
        """Push a signed manifest to the registry.

        The API expects ``{version, manifestHash, files, signatures}`` where
        ``files`` is a list of ``{filename, hash, size}`` and ``signatures``
        is a list of ``{signerDid, algorithm, signatureHex, attestationType}``.

        Args:
            manifest: The signed model manifest to push.
            namespace: org/model-name slug.

        Returns:
            Response dict from the API.

        Raises:
            ValueError: If the manifest has no signatures.
            RegistryError: On API failure.
        """
        if not manifest.signatures:
            raise ValueError("Cannot push an unsigned manifest. Sign it first.")

        import hashlib as _hashlib

        url = f"{self.api_url}/api/models/{namespace}/versions"

        # Build the payload shape expected by the versions API
        manifest_hash = _hashlib.sha3_256(manifest._canonical_bytes()).hexdigest()
        payload: dict[str, Any] = {
            "version": manifest.model.version or "0.0.1",
            "manifestHash": manifest_hash,
            "files": [
                {
                    "filename": f.path,
                    "hash": f.hash_value,
                    "size": f.size,
                }
                for f in manifest.files
            ],
            "signatures": [
                {
                    "signerDid": s.signer,
                    "algorithm": s.algorithm,
                    "signatureHex": s.signature,
                    "attestationType": s.attestation_type,
                }
                for s in manifest.signatures
            ],
        }

        resp = httpx.post(url, json=payload, headers=self._headers(), timeout=60)
        self._raise_for_status(resp)
        return resp.json()  # type: ignore[no-any-return]

    def pull(self, namespace: str) -> dict[str, Any]:
        """Pull model info from the registry.

        Args:
            namespace: org/model-name slug.

        Returns:
            Dict with model info, files, and signatures.
        """
        url = f"{self.api_url}/api/models/{namespace}"
        resp = httpx.get(url, headers=self._headers(auth=False), timeout=30)
        self._raise_for_status(resp)
        return resp.json()  # type: ignore[no-any-return]

    def verify(self, namespace: str) -> dict[str, Any]:
        """Verify a model's signatures via the registry.

        Args:
            namespace: org/model-name slug.

        Returns:
            Dict with verification status and signature details.
        """
        url = f"{self.api_url}/api/models/{namespace}/verify"
        resp = httpx.get(url, headers=self._headers(auth=False), timeout=30)
        self._raise_for_status(resp)
        return resp.json()  # type: ignore[no-any-return]

    def search(self, query: str) -> list[dict[str, Any]]:
        """Search models in the registry.

        Args:
            query: Free-text search query.

        Returns:
            List of matching model dicts.
        """
        url = f"{self.api_url}/api/models"
        resp = httpx.get(
            url,
            params={"q": query},
            headers=self._headers(auth=False),
            timeout=30,
        )
        self._raise_for_status(resp)
        data = resp.json()
        # API may return {"models": [...]} or a bare list
        if isinstance(data, list):
            return data
        return data.get("models", data.get("results", []))

    def list_user_models(self) -> list[dict[str, Any]]:
        """List models belonging to the authenticated user.

        Returns:
            List of model dicts.
        """
        url = f"{self.api_url}/api/users/me"
        resp = httpx.get(url, headers=self._headers(), timeout=30)
        self._raise_for_status(resp)
        data = resp.json()
        return data.get("models", [])

    def create_model(self, namespace: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create a new model entry in the registry.

        Args:
            namespace: org/model-name slug (e.g. "org/model-name").
            metadata: Optional model metadata dict (name, author, description, etc.).

        Returns:
            Response dict from the API.
        """
        url = f"{self.api_url}/api/models"

        # Derive name and author from the slug if not provided in metadata
        parts = namespace.split("/", 1)
        if len(parts) == 2:
            default_author, default_name = parts
        else:
            default_author = "unknown"
            default_name = parts[0]

        payload: dict[str, Any] = {
            "slug": namespace,
            "name": default_name,
            "author": default_author,
        }
        if metadata:
            payload.update(metadata)

        resp = httpx.post(url, json=payload, headers=self._headers(), timeout=30)
        self._raise_for_status(resp)
        return resp.json()  # type: ignore[no-any-return]
