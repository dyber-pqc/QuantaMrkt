"""On-device AI artifacts (model weights, credentials, adapters) - data structures."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class ArtifactKind(str, Enum):
    """Kinds of artifacts stored in a device secure enclave."""

    MODEL_WEIGHTS = "model-weights"
    LORA_ADAPTER = "lora-adapter"
    TOKENIZER = "tokenizer"
    CREDENTIAL = "credential"
    BIOMETRIC_TEMPLATE = "biometric-template"
    INFERENCE_CACHE = "inference-cache"
    SAFETY_MODEL = "safety-model"
    OTHER = "other"


@dataclass(frozen=True)
class ArtifactMetadata:
    """Non-secret metadata about an artifact."""

    artifact_id: str
    name: str
    kind: ArtifactKind
    version: str = ""
    app_bundle_id: str = ""
    size_bytes: int = 0
    created_at: str = ""
    device_id: str = ""
    model_did: str = ""
    tags: tuple[str, ...] = ()
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["kind"] = self.kind.value
        d["tags"] = list(self.tags)
        return d


@dataclass
class EnclaveArtifact:
    """A plaintext artifact - only exists inside an unlocked EnclaveVault."""

    metadata: ArtifactMetadata
    content: bytes

    @staticmethod
    def content_hash(data: bytes) -> str:
        return hashlib.sha3_256(data).hexdigest()

    def sha3_256_hex(self) -> str:
        return self.content_hash(self.content)


@dataclass
class EncryptedArtifact:
    """AES-256-GCM encrypted artifact stored in the enclave-backed store."""

    metadata: ArtifactMetadata
    nonce: str
    ciphertext: str
    content_hash: str
    key_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
            "content_hash": self.content_hash,
            "key_id": self.key_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EncryptedArtifact:
        meta = data["metadata"]
        return cls(
            metadata=ArtifactMetadata(
                artifact_id=meta["artifact_id"],
                name=meta["name"],
                kind=ArtifactKind(meta["kind"]),
                version=meta.get("version", ""),
                app_bundle_id=meta.get("app_bundle_id", ""),
                size_bytes=int(meta.get("size_bytes", 0)),
                created_at=meta.get("created_at", ""),
                device_id=meta.get("device_id", ""),
                model_did=meta.get("model_did", ""),
                tags=tuple(meta.get("tags", [])),
                description=meta.get("description", ""),
            ),
            nonce=data["nonce"],
            ciphertext=data["ciphertext"],
            content_hash=data["content_hash"],
            key_id=data["key_id"],
        )
