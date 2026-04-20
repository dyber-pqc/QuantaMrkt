"""ReasoningTrace - ordered list of steps; SealedTrace is a signed finalization."""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from pqc_reasoning_ledger.errors import ChainBrokenError, TraceSealedError
from pqc_reasoning_ledger.step import ReasoningStep


@dataclass
class TraceMetadata:
    """Non-step metadata describing a reasoning trace."""

    trace_id: str
    model_did: str              # DID of the model that produced this trace
    model_version: str
    task: str = ""              # e.g. "contract_review" | "medical_diagnosis"
    actor_did: str = ""         # who invoked the model
    session_id: str = ""
    domain: str = ""            # e.g. "legal" | "medical" | "finance"
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReasoningTrace:
    """A live, mutable reasoning trace accumulated during inference."""

    metadata: TraceMetadata
    steps: list[ReasoningStep] = field(default_factory=list)
    sealed: bool = False

    @classmethod
    def create(
        cls,
        model_did: str,
        model_version: str,
        task: str = "",
        actor_did: str = "",
        session_id: str = "",
        domain: str = "",
    ) -> ReasoningTrace:
        return cls(
            metadata=TraceMetadata(
                trace_id=f"urn:pqc-trace:{uuid.uuid4().hex}",
                model_did=model_did,
                model_version=model_version,
                task=task,
                actor_did=actor_did,
                session_id=session_id,
                domain=domain,
                created_at=datetime.now(timezone.utc).isoformat(),
            ),
        )

    @property
    def current_hash(self) -> str:
        """The chain-tip hash - what the next step should reference as its previous."""
        if not self.steps:
            return "0" * 64
        return self.steps[-1].step_hash

    def append(self, step: ReasoningStep) -> None:
        if self.sealed:
            raise TraceSealedError(f"trace {self.metadata.trace_id} is sealed")
        if step.previous_step_hash != self.current_hash:
            raise ChainBrokenError(
                f"step previous_step_hash {step.previous_step_hash[:16]}... does not match "
                f"current chain tip {self.current_hash[:16]}..."
            )
        if step.step_number != len(self.steps) + 1:
            raise ChainBrokenError(
                f"step_number {step.step_number} != expected {len(self.steps) + 1}"
            )
        # Verify step_hash was correctly computed
        expected = step.compute_step_hash()
        if step.step_hash != expected:
            raise ChainBrokenError(
                f"step_hash mismatch: declared={step.step_hash[:16]}..., "
                f"expected={expected[:16]}..."
            )
        self.steps.append(step)

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "steps": [s.to_dict() for s in self.steps],
            "sealed": self.sealed,
        }


@dataclass
class SealedTrace:
    """A sealed, ML-DSA signed ReasoningTrace with Merkle root over step hashes."""

    metadata: TraceMetadata
    steps: list[ReasoningStep]
    final_chain_hash: str       # step_hash of last step
    merkle_root: str            # Merkle root over step_hash values
    step_count: int
    sealed_at: str
    signer_did: str = ""
    algorithm: str = ""
    signature: str = ""         # hex
    public_key: str = ""        # hex

    def canonical_bytes(self) -> bytes:
        payload = {
            "metadata": self.metadata.to_dict(),
            "step_hashes": [s.step_hash for s in self.steps],
            "final_chain_hash": self.final_chain_hash,
            "merkle_root": self.merkle_root,
            "step_count": self.step_count,
            "sealed_at": self.sealed_at,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "steps": [s.to_dict() for s in self.steps],
            "final_chain_hash": self.final_chain_hash,
            "merkle_root": self.merkle_root,
            "step_count": self.step_count,
            "sealed_at": self.sealed_at,
            "signer_did": self.signer_did,
            "algorithm": self.algorithm,
            "signature": self.signature,
            "public_key": self.public_key,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SealedTrace:
        meta = data["metadata"]
        return cls(
            metadata=TraceMetadata(**meta),
            steps=[ReasoningStep.from_dict(s) for s in data.get("steps", [])],
            final_chain_hash=data["final_chain_hash"],
            merkle_root=data["merkle_root"],
            step_count=int(data["step_count"]),
            sealed_at=data["sealed_at"],
            signer_did=data.get("signer_did", ""),
            algorithm=data.get("algorithm", ""),
            signature=data.get("signature", ""),
            public_key=data.get("public_key", ""),
        )

    @classmethod
    def from_json(cls, blob: str) -> SealedTrace:
        return cls.from_dict(json.loads(blob))
