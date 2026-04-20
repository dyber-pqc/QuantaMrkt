"""InferenceEvent - one AI decision worth recording."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class InferenceEvent:
    """A single AI inference event.

    We DO NOT store raw input/output (privacy). We store SHA3-256 hashes of
    the canonical input and output so forensic investigators can verify a
    specific claimed-input matches what the model actually saw.
    """

    event_id: str
    timestamp: str
    model_did: str                        # did:pqaid:... of the model
    model_version: str
    input_hash: str                       # SHA3-256 hex of canonical input
    output_hash: str                      # SHA3-256 hex of canonical output
    reasoning_chain_hash: str = ""        # hash over chain-of-thought steps
    decision_type: str = ""               # 'classification' | 'generation' | 'tool_call' | ...
    decision_label: str = ""              # short label (e.g. 'approve' | 'deny')
    actor_did: str = ""                   # who invoked the model (user/agent DID)
    session_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        model_did: str,
        model_version: str,
        input_bytes: bytes,
        output_bytes: bytes,
        reasoning_bytes: bytes | None = None,
        decision_type: str = "",
        decision_label: str = "",
        actor_did: str = "",
        session_id: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> InferenceEvent:
        return cls(
            event_id=f"urn:pqc-audit-evt:{uuid.uuid4().hex}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            model_did=model_did,
            model_version=model_version,
            input_hash=hashlib.sha3_256(input_bytes).hexdigest(),
            output_hash=hashlib.sha3_256(output_bytes).hexdigest(),
            reasoning_chain_hash=(
                hashlib.sha3_256(reasoning_bytes).hexdigest() if reasoning_bytes else ""
            ),
            decision_type=decision_type,
            decision_label=decision_label,
            actor_did=actor_did,
            session_id=session_id,
            metadata=dict(metadata or {}),
        )

    def canonical_bytes(self) -> bytes:
        """Deterministic serialization; leaf hash in Merkle tree."""
        payload = {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "model_did": self.model_did,
            "model_version": self.model_version,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "reasoning_chain_hash": self.reasoning_chain_hash,
            "decision_type": self.decision_type,
            "decision_label": self.decision_label,
            "actor_did": self.actor_did,
            "session_id": self.session_id,
            "metadata": self.metadata,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def leaf_hash(self) -> str:
        return hashlib.sha3_256(self.canonical_bytes()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InferenceEvent:
        return cls(**data)

    def to_jsonl(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"))
