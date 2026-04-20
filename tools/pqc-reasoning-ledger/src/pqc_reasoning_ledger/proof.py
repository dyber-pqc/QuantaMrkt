"""StepInclusionProof + ReasoningProver - prove a specific step is in a sealed trace."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from pqc_reasoning_ledger.errors import StepNotFoundError
from pqc_reasoning_ledger.merkle import InclusionProof, build_proof, verify_inclusion
from pqc_reasoning_ledger.step import ReasoningStep
from pqc_reasoning_ledger.trace import SealedTrace


@dataclass
class StepInclusionProof:
    """Inclusion proof for a single step in a sealed trace."""

    step: ReasoningStep
    proof: InclusionProof
    trace_id: str
    merkle_root: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step.to_dict(),
            "proof": asdict(self.proof),
            "trace_id": self.trace_id,
            "merkle_root": self.merkle_root,
        }


class ReasoningProver:
    """Produce and verify inclusion proofs for steps in sealed traces."""

    @staticmethod
    def prove_step(sealed: SealedTrace, step_id: str) -> StepInclusionProof:
        idx: int | None = None
        for i, s in enumerate(sealed.steps):
            if s.step_id == step_id:
                idx = i
                break
        if idx is None:
            raise StepNotFoundError(
                f"no step with id {step_id} in trace {sealed.metadata.trace_id}"
            )
        leaves = [s.step_hash for s in sealed.steps]
        proof = build_proof(leaves, idx, sealed.merkle_root)
        return StepInclusionProof(
            step=sealed.steps[idx],
            proof=proof,
            trace_id=sealed.metadata.trace_id,
            merkle_root=sealed.merkle_root,
        )

    @staticmethod
    def verify_proof(proof: StepInclusionProof) -> bool:
        expected_leaf = proof.step.step_hash
        if expected_leaf != proof.proof.leaf_hash:
            return False
        if proof.proof.root != proof.merkle_root:
            return False
        return verify_inclusion(proof.proof)
