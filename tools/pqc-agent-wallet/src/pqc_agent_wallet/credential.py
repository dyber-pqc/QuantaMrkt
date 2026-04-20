"""Credential data structures."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class CredentialMetadata:
    """Non-secret metadata about a credential."""

    name: str
    scheme: str = "api-key"  # api-key | oauth | password | cert | token
    service: str = ""  # e.g. "openai", "anthropic", "postgres"
    description: str = ""
    created_at: str = ""
    rotated_at: str = ""
    expires_at: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CredentialMetadata:
        return cls(
            name=data["name"],
            scheme=data.get("scheme", "api-key"),
            service=data.get("service", ""),
            description=data.get("description", ""),
            created_at=data.get("created_at", ""),
            rotated_at=data.get("rotated_at", ""),
            expires_at=data.get("expires_at", ""),
            tags=list(data.get("tags", [])),
        )


@dataclass
class Credential:
    """A stored credential. The `value` is plaintext only when wallet is unlocked."""

    metadata: CredentialMetadata
    value: str = ""  # secret in plaintext (only when unlocked)

    def to_safe_dict(self) -> dict[str, Any]:
        """Serialize without the secret (for logging or public display)."""
        return {
            "metadata": self.metadata.to_dict(),
            "value": "<redacted>",
        }
