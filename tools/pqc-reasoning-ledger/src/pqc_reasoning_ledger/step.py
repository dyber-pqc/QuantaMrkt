"""ReasoningStep - one hash-chained unit of thought."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class StepKind(str, Enum):
    """Types of reasoning steps - the symbolic vocabulary."""

    THOUGHT = "thought"                 # free-form reasoning statement
    OBSERVATION = "observation"         # observation about input or retrieved data
    HYPOTHESIS = "hypothesis"           # a tentative conclusion
    DEDUCTION = "deduction"             # logical deduction from prior steps
    RETRIEVAL = "retrieval"             # fetching external knowledge
    TOOL_CALL = "tool-call"             # calling an external tool / function
    TOOL_RESULT = "tool-result"
    SELF_CRITIQUE = "self-critique"     # model critiquing its own prior step
    REFINEMENT = "refinement"           # updated answer after critique
    DECISION = "decision"               # final decision / answer
    META = "meta"                       # metadata about the run


@dataclass(frozen=True)
class StepReference:
    """A reference from one step to an earlier step
    (e.g. 'deduction references observation X')."""

    step_id: str
    relationship: str  # "depends-on" | "refutes" | "refines" | "cites"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReasoningStep:
    """One step in a chain-of-thought reasoning trace.

    Every step is hashed with:
        SHA3-256( previous_hash || canonical_bytes(step_payload) )
    Steps chain via previous_step_hash, so any tampering of an intermediate
    step invalidates every step after it.
    """

    step_id: str
    step_number: int                    # 1-based position within the trace
    kind: StepKind
    content: str                        # the actual reasoning text
    timestamp: str
    content_hash: str = ""              # SHA3-256 of content
    step_hash: str = ""                 # chain hash: SHA3-256(prev_hash || canonical_bytes)
    previous_step_hash: str = "0" * 64
    references: list[StepReference] = field(default_factory=list)
    confidence: float = 1.0             # 0..1 model's reported confidence in this step
    metadata: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def hash_content(content: str) -> str:
        return hashlib.sha3_256(content.encode("utf-8")).hexdigest()

    def canonical_bytes(self) -> bytes:
        """Deterministic payload for hashing - excludes chain hash."""
        payload = {
            "step_id": self.step_id,
            "step_number": self.step_number,
            "kind": self.kind.value,
            "content_hash": self.content_hash,
            "timestamp": self.timestamp,
            "previous_step_hash": self.previous_step_hash,
            "references": [r.to_dict() for r in self.references],
            "confidence": self.confidence,
            "metadata": self.metadata,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def compute_step_hash(self) -> str:
        """SHA3-256 over (previous_step_hash || canonical_bytes)."""
        prev = (
            bytes.fromhex(self.previous_step_hash)
            if self.previous_step_hash
            else b"\x00" * 32
        )
        return hashlib.sha3_256(prev + self.canonical_bytes()).hexdigest()

    @classmethod
    def create(
        cls,
        kind: StepKind,
        content: str,
        step_number: int,
        previous_step_hash: str = "0" * 64,
        references: list[StepReference] | None = None,
        confidence: float = 1.0,
        metadata: dict[str, Any] | None = None,
    ) -> ReasoningStep:
        step_id = f"urn:pqc-step:{uuid.uuid4().hex}"
        now = datetime.now(timezone.utc).isoformat()
        content_hash = cls.hash_content(content)
        step = cls(
            step_id=step_id,
            step_number=step_number,
            kind=kind,
            content=content,
            timestamp=now,
            content_hash=content_hash,
            step_hash="",
            previous_step_hash=previous_step_hash,
            references=list(references or []),
            confidence=confidence,
            metadata=dict(metadata or {}),
        )
        step.step_hash = step.compute_step_hash()
        return step

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["kind"] = self.kind.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReasoningStep:
        return cls(
            step_id=data["step_id"],
            step_number=int(data["step_number"]),
            kind=StepKind(data["kind"]),
            content=data["content"],
            timestamp=data["timestamp"],
            content_hash=data.get("content_hash", ""),
            step_hash=data.get("step_hash", ""),
            previous_step_hash=data.get("previous_step_hash", "0" * 64),
            references=[StepReference(**r) for r in data.get("references", [])],
            confidence=float(data.get("confidence", 1.0)),
            metadata=dict(data.get("metadata", {})),
        )
