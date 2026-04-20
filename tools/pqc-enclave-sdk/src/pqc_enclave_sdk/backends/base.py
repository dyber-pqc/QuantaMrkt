"""EnclaveBackend base - platform integration point."""

from __future__ import annotations

from abc import ABC, abstractmethod

from pqc_enclave_sdk.artifact import EncryptedArtifact


class EnclaveBackend(ABC):
    """Abstract base for platform-specific enclave backends.

    A backend's responsibilities:
      1. Identify the device (device_id property)
      2. Store/load session keys within the enclave
      3. Persist EncryptedArtifacts via the device's secure storage

    Implementations MUST NEVER store the symmetric key in plaintext on the
    untrusted host filesystem - it lives only inside the enclave.
    """

    name: str = ""
    platform: str = ""
    device_id: str = ""
    device_model: str = ""
    enclave_vendor: str = ""

    @abstractmethod
    def store_session_key(self, key_id: str, key: bytes, expires_at: str) -> None:
        """Store a derived session key inside the enclave."""

    @abstractmethod
    def load_session_key(self, key_id: str) -> bytes | None:
        """Retrieve a session key from the enclave by ID."""

    @abstractmethod
    def save_artifacts(self, artifacts: dict[str, EncryptedArtifact]) -> None:
        """Persist encrypted artifacts to device storage."""

    @abstractmethod
    def load_artifacts(self) -> dict[str, EncryptedArtifact]:
        """Load encrypted artifacts from device storage."""
