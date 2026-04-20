"""In-memory reference backend. NOT FOR PRODUCTION - tests and demos only."""

from __future__ import annotations

from pqc_enclave_sdk.artifact import EncryptedArtifact
from pqc_enclave_sdk.backends.base import EnclaveBackend


class InMemoryEnclaveBackend(EnclaveBackend):
    """Deterministic in-memory backend.

    Suitable for tests, tutorials, and CI - no dependency on any platform
    secure element. All data lives in the Python process and is lost on exit.
    """

    name = "in-memory"
    platform = "in-memory"
    enclave_vendor = "in-memory"

    def __init__(
        self,
        device_id: str = "test-device-0",
        device_model: str = "in-memory",
    ) -> None:
        self.device_id = device_id
        self.device_model = device_model
        self._session_keys: dict[str, tuple[bytes, str]] = {}
        self._artifacts: dict[str, EncryptedArtifact] = {}

    def store_session_key(self, key_id: str, key: bytes, expires_at: str) -> None:
        self._session_keys[key_id] = (key, expires_at)

    def load_session_key(self, key_id: str) -> bytes | None:
        if key_id in self._session_keys:
            return self._session_keys[key_id][0]
        return None

    def save_artifacts(self, artifacts: dict[str, EncryptedArtifact]) -> None:
        self._artifacts = dict(artifacts)

    def load_artifacts(self) -> dict[str, EncryptedArtifact]:
        return dict(self._artifacts)
