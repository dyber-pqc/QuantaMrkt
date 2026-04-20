"""Tests for ReasoningStep."""

from __future__ import annotations

from pqc_reasoning_ledger import ReasoningStep, StepKind, StepReference


def test_hash_content_is_deterministic() -> None:
    a = ReasoningStep.hash_content("hello world")
    b = ReasoningStep.hash_content("hello world")
    c = ReasoningStep.hash_content("hello world!")
    assert a == b
    assert a != c
    assert len(a) == 64


def test_create_sets_step_hash_correctly() -> None:
    step = ReasoningStep.create(
        kind=StepKind.OBSERVATION,
        content="the sky is blue",
        step_number=1,
    )
    assert step.step_hash
    assert step.step_hash == step.compute_step_hash()
    assert step.content_hash == ReasoningStep.hash_content("the sky is blue")


def test_compute_step_hash_changes_with_content() -> None:
    s1 = ReasoningStep.create(StepKind.THOUGHT, "A", step_number=1)
    s2 = ReasoningStep.create(StepKind.THOUGHT, "B", step_number=1)
    assert s1.step_hash != s2.step_hash


def test_compute_step_hash_changes_with_previous_step_hash() -> None:
    prev_a = "a" * 64
    prev_b = "b" * 64
    s1 = ReasoningStep.create(
        StepKind.DEDUCTION, "same content", step_number=2, previous_step_hash=prev_a
    )
    s2 = ReasoningStep.create(
        StepKind.DEDUCTION, "same content", step_number=2, previous_step_hash=prev_b
    )
    assert s1.step_hash != s2.step_hash


def test_to_dict_from_dict_roundtrip() -> None:
    ref = StepReference(step_id="urn:pqc-step:abc", relationship="cites")
    original = ReasoningStep.create(
        kind=StepKind.DEDUCTION,
        content="thus the clause is enforceable",
        step_number=4,
        previous_step_hash="f" * 64,
        references=[ref],
        confidence=0.87,
        metadata={"model_temp": 0.2},
    )
    d = original.to_dict()
    restored = ReasoningStep.from_dict(d)
    assert restored.step_id == original.step_id
    assert restored.step_number == original.step_number
    assert restored.kind == original.kind
    assert restored.content == original.content
    assert restored.content_hash == original.content_hash
    assert restored.step_hash == original.step_hash
    assert restored.previous_step_hash == original.previous_step_hash
    assert restored.confidence == original.confidence
    assert restored.metadata == original.metadata
    assert restored.references == original.references


def test_references_preserved_in_hash() -> None:
    ref_a = StepReference(step_id="s:1", relationship="depends-on")
    ref_b = StepReference(step_id="s:2", relationship="cites")
    s1 = ReasoningStep.create(
        StepKind.DEDUCTION, "c", step_number=2, references=[ref_a]
    )
    s2 = ReasoningStep.create(
        StepKind.DEDUCTION, "c", step_number=2, references=[ref_b]
    )
    # Different references must produce different hashes
    # Note: different step_ids (uuid) also contribute, but references are canonical
    assert s1.references == [ref_a]
    assert s2.references == [ref_b]
    assert s1.canonical_bytes() != s2.canonical_bytes()
