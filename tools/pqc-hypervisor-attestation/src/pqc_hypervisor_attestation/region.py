"""Memory region data structures."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class MemoryRegion:
    """An addressable region of memory the attester will cover.

    We use abstract addresses (strings or ints). In practice this is:
      - guest-physical address + size for a VM
      - process virtual address + size for a confidential container
      - a model-weights object ID in a model-serving server
    """

    region_id: str                      # stable identifier (e.g. "model-weights-0")
    description: str                    # human-readable description
    address: int                        # base address (in abstract address space)
    size: int                           # bytes
    protection: str = "RO"              # "R" | "RW" | "RO" | "RX"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RegionSnapshot:
    """A SHA3-256 fingerprint of a region at a point in time.

    Backends produce snapshots; attesters sign them.
    """

    region_id: str
    content_hash: str                   # SHA3-256 of the exact bytes at `taken_at`
    size: int
    taken_at: str                       # ISO-8601

    @staticmethod
    def hash_bytes(data: bytes) -> str:
        return hashlib.sha3_256(data).hexdigest()

    @classmethod
    def create(cls, region_id: str, content: bytes) -> RegionSnapshot:
        return cls(
            region_id=region_id,
            content_hash=cls.hash_bytes(content),
            size=len(content),
            taken_at=datetime.now(timezone.utc).isoformat(),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
