"""Data record representation.

A training record is an arbitrary piece of training data - a document, an
image, an audio file, a row in a structured dataset. What matters to the
commitment is its content hash.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RecordHash:
    """Wrapper around a leaf hash for type clarity."""

    hex: str

    @property
    def bytes(self) -> bytes:
        return bytes.fromhex(self.hex)

    def __str__(self) -> str:
        return self.hex


@dataclass(frozen=True)
class DataRecord:
    """A single training record - content + optional metadata.

    We hash `content` + canonical JSON of `metadata` to produce the leaf hash.
    The same record (same bytes, same metadata) always produces the same hash.
    """

    content: bytes
    metadata: dict = field(default_factory=dict)

    def canonical_bytes(self) -> bytes:
        """Deterministic serialization combining content and metadata.

        Format: SHA3-256(content) + "|" + canonical_json(metadata)
        We hash content first to handle binary data cleanly.
        """
        content_hash = hashlib.sha3_256(self.content).hexdigest()
        meta_json = json.dumps(
            self.metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        return f"{content_hash}|{meta_json}".encode("utf-8")

    def leaf_hash(self) -> RecordHash:
        """SHA3-256 of the canonical bytes - this is the Merkle leaf value."""
        h = hashlib.sha3_256(self.canonical_bytes()).hexdigest()
        return RecordHash(hex=h)

    def to_dict(self) -> dict[str, Any]:
        """Safe serialization - does NOT include raw content (privacy)."""
        return {
            "content_sha3_256": hashlib.sha3_256(self.content).hexdigest(),
            "content_size": len(self.content),
            "metadata": dict(self.metadata),
            "leaf_hash": self.leaf_hash().hex,
        }
