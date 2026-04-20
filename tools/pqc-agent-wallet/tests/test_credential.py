"""Tests for credential dataclasses."""

from __future__ import annotations

from pqc_agent_wallet.credential import Credential, CredentialMetadata


def test_metadata_roundtrip() -> None:
    meta = CredentialMetadata(
        name="openai",
        scheme="api-key",
        service="openai",
        description="prod key",
        created_at="2026-01-01T00:00:00+00:00",
        rotated_at="",
        expires_at="",
        tags=["prod", "llm"],
    )
    d = meta.to_dict()
    restored = CredentialMetadata.from_dict(d)
    assert restored == meta


def test_credential_to_safe_dict_redacts_value() -> None:
    meta = CredentialMetadata(name="my-key")
    cred = Credential(metadata=meta, value="sk-secret-value")
    safe = cred.to_safe_dict()
    assert safe["value"] == "<redacted>"
    assert "sk-secret-value" not in str(safe)
    assert safe["metadata"]["name"] == "my-key"
