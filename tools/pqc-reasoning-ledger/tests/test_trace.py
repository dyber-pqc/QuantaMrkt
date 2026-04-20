"""Tests for ReasoningTrace."""

from __future__ import annotations

import pytest

from pqc_reasoning_ledger import (
    ChainBrokenError,
    ReasoningStep,
    ReasoningTrace,
    StepKind,
    TraceSealedError,
)


def test_create_populates_trace_id() -> None:
    trace = ReasoningTrace.create(model_did="did:x", model_version="1")
    assert trace.metadata.trace_id.startswith("urn:pqc-trace:")
    assert trace.metadata.created_at
    assert trace.steps == []
    assert trace.sealed is False
    assert trace.current_hash == "0" * 64


def test_append_first_step_sets_current_hash() -> None:
    trace = ReasoningTrace.create(model_did="did:x", model_version="1")
    step = ReasoningStep.create(
        kind=StepKind.THOUGHT,
        content="first thought",
        step_number=1,
        previous_step_hash="0" * 64,
    )
    trace.append(step)
    assert trace.current_hash == step.step_hash
    assert len(trace.steps) == 1


def test_append_chain_broken_raises() -> None:
    trace = ReasoningTrace.create(model_did="did:x", model_version="1")
    # Step 1 ok
    s1 = ReasoningStep.create(StepKind.THOUGHT, "t1", step_number=1)
    trace.append(s1)
    # Step 2 with wrong previous_step_hash
    bad = ReasoningStep.create(
        kind=StepKind.DEDUCTION,
        content="t2",
        step_number=2,
        previous_step_hash="f" * 64,  # wrong
    )
    with pytest.raises(ChainBrokenError):
        trace.append(bad)


def test_append_wrong_step_number_raises() -> None:
    trace = ReasoningTrace.create(model_did="did:x", model_version="1")
    s1 = ReasoningStep.create(StepKind.THOUGHT, "t1", step_number=1)
    trace.append(s1)
    # Step with step_number 3 instead of 2
    bad = ReasoningStep.create(
        kind=StepKind.THOUGHT,
        content="t2",
        step_number=3,
        previous_step_hash=trace.current_hash,
    )
    with pytest.raises(ChainBrokenError):
        trace.append(bad)


def test_sealed_trace_rejects_append() -> None:
    trace = ReasoningTrace.create(model_did="did:x", model_version="1")
    s1 = ReasoningStep.create(StepKind.THOUGHT, "t1", step_number=1)
    trace.append(s1)
    trace.sealed = True
    s2 = ReasoningStep.create(
        StepKind.THOUGHT, "t2", step_number=2, previous_step_hash=trace.current_hash
    )
    with pytest.raises(TraceSealedError):
        trace.append(s2)
