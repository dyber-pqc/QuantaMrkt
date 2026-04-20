"""Tests for ReasoningProver inclusion proofs."""

from __future__ import annotations

import pytest

from pqc_reasoning_ledger import (
    ReasoningProver,
    ReasoningRecorder,
    StepNotFoundError,
)


def _build_sealed(recorder: ReasoningRecorder):
    recorder.record_observation("step 1")
    recorder.record_hypothesis("step 2")
    recorder.record_deduction("step 3")
    recorder.record_self_critique("step 4")
    recorder.record_decision("step 5")
    return recorder.seal()


def test_prove_step_existing_returns_proof(
    sample_trace_started: ReasoningRecorder,
) -> None:
    sealed = _build_sealed(sample_trace_started)
    target = sealed.steps[2]
    proof = ReasoningProver.prove_step(sealed, target.step_id)
    assert proof.step.step_id == target.step_id
    assert proof.trace_id == sealed.metadata.trace_id
    assert proof.merkle_root == sealed.merkle_root
    assert proof.proof.index == 2
    assert proof.proof.leaf_hash == target.step_hash


def test_verify_proof_passes(
    sample_trace_started: ReasoningRecorder,
) -> None:
    sealed = _build_sealed(sample_trace_started)
    for idx in range(len(sealed.steps)):
        target = sealed.steps[idx]
        proof = ReasoningProver.prove_step(sealed, target.step_id)
        assert ReasoningProver.verify_proof(proof) is True


def test_prove_step_missing_raises(
    sample_trace_started: ReasoningRecorder,
) -> None:
    sealed = _build_sealed(sample_trace_started)
    with pytest.raises(StepNotFoundError):
        ReasoningProver.prove_step(sealed, "urn:pqc-step:does-not-exist")


def test_verify_proof_fails_on_tampered_step(
    sample_trace_started: ReasoningRecorder,
) -> None:
    sealed = _build_sealed(sample_trace_started)
    target = sealed.steps[1]
    proof = ReasoningProver.prove_step(sealed, target.step_id)
    # Tamper the step's step_hash on the proof so it disagrees with proof.leaf_hash
    proof.step.step_hash = "0" * 64
    assert ReasoningProver.verify_proof(proof) is False
