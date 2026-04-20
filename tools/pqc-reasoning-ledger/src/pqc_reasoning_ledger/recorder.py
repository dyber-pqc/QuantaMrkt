"""ReasoningRecorder - high-level API for building traces and sealing them with ML-DSA."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from quantumshield.core.signatures import sign
from quantumshield.identity.agent import AgentIdentity

from pqc_reasoning_ledger.errors import ReasoningLedgerError
from pqc_reasoning_ledger.merkle import compute_merkle_root
from pqc_reasoning_ledger.step import ReasoningStep, StepKind, StepReference
from pqc_reasoning_ledger.trace import ReasoningTrace, SealedTrace


class ReasoningRecorder:
    """Live recorder: append steps during inference, seal and sign at the end.

    Usage:
        identity = AgentIdentity.create("gpt-legal-advisor-signer")
        rec = ReasoningRecorder(identity)
        rec.begin_trace(
            model_did="did:pqaid:gpt-legal",
            model_version="2.1",
            task="contract-review",
            domain="legal",
        )
        rec.record_observation("Contract contains a liquidated damages clause.")
        rec.record_hypothesis("Clause is likely enforceable under NY law.")
        rec.record_deduction("Based on prior observation and hypothesis...")
        rec.record_decision("Recommend signing with modification to cap at $50k.")
        sealed = rec.seal()
    """

    def __init__(self, identity: AgentIdentity):
        self.identity = identity
        self.trace: ReasoningTrace | None = None

    # -- trace lifecycle ----------------------------------------------------

    def begin_trace(
        self,
        model_did: str,
        model_version: str,
        task: str = "",
        actor_did: str = "",
        session_id: str = "",
        domain: str = "",
    ) -> ReasoningTrace:
        self.trace = ReasoningTrace.create(
            model_did=model_did,
            model_version=model_version,
            task=task,
            actor_did=actor_did,
            session_id=session_id,
            domain=domain,
        )
        return self.trace

    def _require_trace(self) -> ReasoningTrace:
        if self.trace is None:
            raise ReasoningLedgerError("call begin_trace() first")
        return self.trace

    # -- generic step recording --------------------------------------------

    def record(
        self,
        kind: StepKind,
        content: str,
        references: list[StepReference] | None = None,
        confidence: float = 1.0,
        metadata: dict[str, Any] | None = None,
    ) -> ReasoningStep:
        trace = self._require_trace()
        step = ReasoningStep.create(
            kind=kind,
            content=content,
            step_number=len(trace.steps) + 1,
            previous_step_hash=trace.current_hash,
            references=references,
            confidence=confidence,
            metadata=metadata,
        )
        trace.append(step)
        return step

    # -- convenience wrappers for each StepKind ----------------------------

    def record_thought(self, content: str, **kw: Any) -> ReasoningStep:
        return self.record(StepKind.THOUGHT, content, **kw)

    def record_observation(self, content: str, **kw: Any) -> ReasoningStep:
        return self.record(StepKind.OBSERVATION, content, **kw)

    def record_hypothesis(self, content: str, **kw: Any) -> ReasoningStep:
        return self.record(StepKind.HYPOTHESIS, content, **kw)

    def record_deduction(self, content: str, **kw: Any) -> ReasoningStep:
        return self.record(StepKind.DEDUCTION, content, **kw)

    def record_retrieval(self, content: str, **kw: Any) -> ReasoningStep:
        return self.record(StepKind.RETRIEVAL, content, **kw)

    def record_tool_call(self, content: str, **kw: Any) -> ReasoningStep:
        return self.record(StepKind.TOOL_CALL, content, **kw)

    def record_tool_result(self, content: str, **kw: Any) -> ReasoningStep:
        return self.record(StepKind.TOOL_RESULT, content, **kw)

    def record_self_critique(self, content: str, **kw: Any) -> ReasoningStep:
        return self.record(StepKind.SELF_CRITIQUE, content, **kw)

    def record_refinement(self, content: str, **kw: Any) -> ReasoningStep:
        return self.record(StepKind.REFINEMENT, content, **kw)

    def record_decision(self, content: str, **kw: Any) -> ReasoningStep:
        return self.record(StepKind.DECISION, content, **kw)

    # -- sealing -----------------------------------------------------------

    def seal(self) -> SealedTrace:
        trace = self._require_trace()
        if not trace.steps:
            raise ReasoningLedgerError("cannot seal empty trace")
        step_hashes = [s.step_hash for s in trace.steps]
        merkle_root = compute_merkle_root(step_hashes)
        sealed = SealedTrace(
            metadata=trace.metadata,
            steps=list(trace.steps),
            final_chain_hash=trace.current_hash,
            merkle_root=merkle_root,
            step_count=len(trace.steps),
            sealed_at=datetime.now(timezone.utc).isoformat(),
        )
        digest = hashlib.sha3_256(sealed.canonical_bytes()).digest()
        sig = sign(digest, self.identity.signing_keypair)
        sealed.signer_did = self.identity.did
        sealed.algorithm = self.identity.signing_keypair.algorithm.value
        sealed.signature = sig.hex()
        sealed.public_key = self.identity.signing_keypair.public_key.hex()
        trace.sealed = True
        return sealed
