"""AuditSegment - a sealed batch of InferenceEvents with Merkle root + ML-DSA sig."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from pqc_audit_log_fs.event import InferenceEvent
from pqc_audit_log_fs.merkle import compute_merkle_root


@dataclass
class SegmentHeader:
    """Signed header for an AuditSegment."""

    segment_id: str                   # e.g. "segment-00001"
    segment_number: int               # sequential
    created_at: str
    sealed_at: str = ""
    event_count: int = 0
    merkle_root: str = ""             # hex SHA3-256
    previous_segment_root: str = ""   # chain link
    log_id: str = ""                  # stable ID of the log this segment belongs to

    # Populated by LogAppender when sealed:
    signer_did: str = ""
    algorithm: str = ""
    signature: str = ""
    public_key: str = ""

    def canonical_bytes(self) -> bytes:
        payload = {
            "segment_id": self.segment_id,
            "segment_number": self.segment_number,
            "created_at": self.created_at,
            "sealed_at": self.sealed_at,
            "event_count": self.event_count,
            "merkle_root": self.merkle_root,
            "previous_segment_root": self.previous_segment_root,
            "log_id": self.log_id,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SegmentHeader:
        return cls(**data)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class AuditSegment:
    """A sealed batch of events + signed header."""

    header: SegmentHeader
    events: list[InferenceEvent] = field(default_factory=list)

    def recompute_root(self) -> str:
        leaves = [e.leaf_hash() for e in self.events]
        self.header.merkle_root = compute_merkle_root(leaves) if leaves else ""
        self.header.event_count = len(self.events)
        return self.header.merkle_root
