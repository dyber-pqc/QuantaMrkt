"""Tests for ReasoningRecorder."""

from __future__ import annotations

import pytest

from pqc_reasoning_ledger import ReasoningRecorder, StepKind


def test_record_thought_appends_thought_step(
    sample_trace_started: ReasoningRecorder,
) -> None:
    step = sample_trace_started.record_thought("I am thinking")
    assert step.kind == StepKind.THOUGHT
    assert step.content == "I am thinking"
    assert sample_trace_started.trace is not None
    assert sample_trace_started.trace.steps[-1] is step


def test_all_convenience_methods_work(
    sample_trace_started: ReasoningRecorder,
) -> None:
    r = sample_trace_started
    r.record_thought("t")
    r.record_observation("o")
    r.record_hypothesis("h")
    r.record_deduction("d")
    r.record_retrieval("r")
    r.record_tool_call("tc")
    r.record_tool_result("tr")
    r.record_self_critique("sc")
    r.record_refinement("rf")
    r.record_decision("dec")
    assert r.trace is not None
    kinds = [s.kind for s in r.trace.steps]
    assert kinds == [
        StepKind.THOUGHT,
        StepKind.OBSERVATION,
        StepKind.HYPOTHESIS,
        StepKind.DEDUCTION,
        StepKind.RETRIEVAL,
        StepKind.TOOL_CALL,
        StepKind.TOOL_RESULT,
        StepKind.SELF_CRITIQUE,
        StepKind.REFINEMENT,
        StepKind.DECISION,
    ]


def test_record_auto_increments_step_number(
    sample_trace_started: ReasoningRecorder,
) -> None:
    s1 = sample_trace_started.record_thought("one")
    s2 = sample_trace_started.record_thought("two")
    s3 = sample_trace_started.record_thought("three")
    assert s1.step_number == 1
    assert s2.step_number == 2
    assert s3.step_number == 3


def test_steps_chain_via_previous_step_hash(
    sample_trace_started: ReasoningRecorder,
) -> None:
    s1 = sample_trace_started.record_observation("first")
    s2 = sample_trace_started.record_deduction("second")
    s3 = sample_trace_started.record_decision("third")
    assert s1.previous_step_hash == "0" * 64
    assert s2.previous_step_hash == s1.step_hash
    assert s3.previous_step_hash == s2.step_hash


def test_seal_produces_sealed_trace_with_merkle_root(
    sample_trace_started: ReasoningRecorder,
) -> None:
    sample_trace_started.record_observation("a")
    sample_trace_started.record_deduction("b")
    sealed = sample_trace_started.seal()
    assert sealed.step_count == 2
    assert len(sealed.merkle_root) == 64
    assert sealed.final_chain_hash == sealed.steps[-1].step_hash


def test_seal_signs_the_trace(
    sample_trace_started: ReasoningRecorder,
) -> None:
    sample_trace_started.record_decision("x")
    sealed = sample_trace_started.seal()
    assert sealed.signer_did
    assert sealed.algorithm
    assert sealed.signature
    assert sealed.public_key
    assert sealed.signer_did == sample_trace_started.identity.did
    assert (
        sealed.algorithm
        == sample_trace_started.identity.signing_keypair.algorithm.value
    )


def test_seal_empty_trace_raises(
    sample_trace_started: ReasoningRecorder,
) -> None:
    with pytest.raises(Exception):
        sample_trace_started.seal()
