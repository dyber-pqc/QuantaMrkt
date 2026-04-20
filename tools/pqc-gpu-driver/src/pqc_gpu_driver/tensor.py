"""Encrypted tensor envelope for CPU<->GPU transfers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class TensorMetadata:
    """Non-secret metadata about a tensor transfer."""

    tensor_id: str                          # stable id within a session
    name: str = ""                          # e.g. "model.dense_1.weights"
    dtype: str = "float32"
    shape: tuple[int, ...] = ()
    size_bytes: int = 0
    transfer_direction: str = "cpu_to_gpu"  # "cpu_to_gpu" | "gpu_to_cpu"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["shape"] = list(self.shape)
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TensorMetadata:
        return cls(
            tensor_id=data["tensor_id"],
            name=data.get("name", ""),
            dtype=data.get("dtype", "float32"),
            shape=tuple(data.get("shape", [])),
            size_bytes=int(data.get("size_bytes", 0)),
            transfer_direction=data.get("transfer_direction", "cpu_to_gpu"),
        )


@dataclass
class EncryptedTensor:
    """AES-256-GCM encrypted tensor bytes + metadata authenticated via AAD."""

    metadata: TensorMetadata
    nonce: str                              # hex (12 bytes = 24 hex chars)
    ciphertext: str                         # hex
    sequence_number: int                    # strictly-increasing per session

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
            "sequence_number": self.sequence_number,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EncryptedTensor:
        return cls(
            metadata=TensorMetadata.from_dict(data["metadata"]),
            nonce=data["nonce"],
            ciphertext=data["ciphertext"],
            sequence_number=int(data["sequence_number"]),
        )
