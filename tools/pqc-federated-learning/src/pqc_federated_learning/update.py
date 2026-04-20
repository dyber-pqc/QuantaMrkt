"""Gradient update data structures."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class GradientTensor:
    """A named tensor in a gradient update.

    We keep values as a flat list of floats so this library has NO dependency
    on numpy/torch. Users can trivially convert with `np.array(t.values).reshape(t.shape)`.
    """

    name: str  # layer name, e.g. "dense_1.weights"
    shape: tuple[int, ...]
    values: tuple[float, ...]  # flat, row-major

    def __post_init__(self) -> None:
        expected = 1
        for d in self.shape:
            expected *= d
        if expected != len(self.values):
            raise ValueError(
                f"shape {self.shape} implies {expected} values, got {len(self.values)}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "shape": list(self.shape),
            "values": list(self.values),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GradientTensor:
        return cls(
            name=data["name"],
            shape=tuple(data["shape"]),
            values=tuple(float(v) for v in data["values"]),
        )


@dataclass(frozen=True)
class ClientUpdateMetadata:
    """Non-secret metadata describing a client's update."""

    client_did: str
    round_id: str
    model_id: str  # which model is being trained
    num_samples: int  # size of local training set (used as weight in FedAvg)
    epochs: int = 1
    local_loss: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ClientUpdate:
    """Signed gradient update from a client."""

    metadata: ClientUpdateMetadata
    tensors: list[GradientTensor]
    created_at: str = ""
    content_hash: str = ""  # SHA3-256 over canonical serialization
    signer_did: str = ""
    algorithm: str = ""
    signature: str = ""  # hex
    public_key: str = ""  # hex
    signed_at: str = ""

    def canonical_bytes(self) -> bytes:
        payload = {
            "metadata": self.metadata.to_dict(),
            "tensors": [t.to_dict() for t in self.tensors],
            "created_at": self.created_at,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    @staticmethod
    def compute_content_hash(
        metadata: ClientUpdateMetadata,
        tensors: list[GradientTensor],
        created_at: str,
    ) -> str:
        payload = {
            "metadata": metadata.to_dict(),
            "tensors": [t.to_dict() for t in tensors],
            "created_at": created_at,
        }
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return hashlib.sha3_256(canonical).hexdigest()

    @classmethod
    def create(
        cls,
        metadata: ClientUpdateMetadata,
        tensors: list[GradientTensor],
    ) -> ClientUpdate:
        now = datetime.now(timezone.utc).isoformat()
        u = cls(metadata=metadata, tensors=list(tensors), created_at=now)
        u.content_hash = cls.compute_content_hash(metadata, tensors, now)
        return u

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "tensors": [t.to_dict() for t in self.tensors],
            "created_at": self.created_at,
            "content_hash": self.content_hash,
            "signer_did": self.signer_did,
            "algorithm": self.algorithm,
            "signature": self.signature,
            "public_key": self.public_key,
            "signed_at": self.signed_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ClientUpdate:
        meta = data["metadata"]
        return cls(
            metadata=ClientUpdateMetadata(
                client_did=meta["client_did"],
                round_id=meta["round_id"],
                model_id=meta["model_id"],
                num_samples=int(meta["num_samples"]),
                epochs=int(meta.get("epochs", 1)),
                local_loss=float(meta.get("local_loss", 0.0)),
            ),
            tensors=[GradientTensor.from_dict(t) for t in data["tensors"]],
            created_at=data.get("created_at", ""),
            content_hash=data.get("content_hash", ""),
            signer_did=data.get("signer_did", ""),
            algorithm=data.get("algorithm", ""),
            signature=data.get("signature", ""),
            public_key=data.get("public_key", ""),
            signed_at=data.get("signed_at", ""),
        )
