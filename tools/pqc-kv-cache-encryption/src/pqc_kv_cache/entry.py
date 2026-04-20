"""KV cache entry data structures."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class EntryMetadata:
    """Non-secret metadata about a KV cache entry."""

    tenant_id: str
    session_id: str
    layer_idx: int
    position: int                     # token position in sequence
    token_id: int = -1                # optional vocab id (for debugging; not required)
    kv_role: str = "both"             # "key" | "value" | "both"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class KVCacheEntry:
    """Plaintext KV cache entry - only exists inside TenantSession scope."""

    metadata: EntryMetadata
    key_tensor_bytes: bytes           # raw bytes of the K vector for this position
    value_tensor_bytes: bytes         # raw bytes of the V vector for this position

    def plaintext_size(self) -> int:
        return len(self.key_tensor_bytes) + len(self.value_tensor_bytes)


@dataclass
class EncryptedEntry:
    """AES-256-GCM encrypted KV cache entry."""

    metadata: EntryMetadata
    nonce: str                        # hex
    ciphertext: str                   # hex (contains both K and V concatenated)
    key_len: int                      # bytes of K portion (V starts after)
    sequence_number: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
            "key_len": self.key_len,
            "sequence_number": self.sequence_number,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EncryptedEntry:
        meta = data["metadata"]
        return cls(
            metadata=EntryMetadata(
                tenant_id=meta["tenant_id"],
                session_id=meta["session_id"],
                layer_idx=int(meta["layer_idx"]),
                position=int(meta["position"]),
                token_id=int(meta.get("token_id", -1)),
                kv_role=meta.get("kv_role", "both"),
            ),
            nonce=data["nonce"],
            ciphertext=data["ciphertext"],
            key_len=int(data["key_len"]),
            sequence_number=int(data["sequence_number"]),
        )
