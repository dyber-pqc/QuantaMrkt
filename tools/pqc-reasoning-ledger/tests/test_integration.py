"""End-to-end integration tests."""

from __future__ import annotations

from pqc_reasoning_ledger import (
    ReasoningProver,
    ReasoningRecorder,
    SealedTrace,
    TraceVerifier,
)


def test_full_lifecycle(sample_trace_started: ReasoningRecorder) -> None:
    r = sample_trace_started
    r.record_observation("Patient reports chest pain and shortness of breath")
    r.record_retrieval("Relevant guideline: ACC/AHA 2021 chest-pain evaluation")
    r.record_hypothesis("Possible acute coronary syndrome")
    r.record_deduction("Given observation + guideline, ACS cannot be ruled out")
    r.record_decision("Recommend immediate troponin + ECG")

    sealed = r.seal()
    assert sealed.step_count == 5

    # Verify end-to-end
    result = TraceVerifier.verify(sealed)
    assert result.fully_verified

    # Round-trip through JSON (proves serialization)
    blob = sealed.to_json()
    restored = SealedTrace.from_json(blob)
    assert TraceVerifier.verify(restored).fully_verified

    # Prove step 3 (hypothesis)
    target = sealed.steps[2]
    proof = ReasoningProver.prove_step(sealed, target.step_id)
    assert ReasoningProver.verify_proof(proof)


def test_tampered_step_between_seal_and_verify_flagged(
    sample_trace_started: ReasoningRecorder,
) -> None:
    r = sample_trace_started
    r.record_observation("A")
    r.record_deduction("B")
    r.record_decision("C")
    sealed = r.seal()

    # Flip a byte of step 1's content_hash - should break the chain
    sealed.steps[1].content_hash = (
        ("0" if sealed.steps[1].content_hash[0] != "0" else "f")
        + sealed.steps[1].content_hash[1:]
    )
    result = TraceVerifier.verify(sealed)
    assert result.valid is False
    assert result.chain_intact is False


def test_byzantine_swap_final_decision(
    sample_trace_started: ReasoningRecorder,
) -> None:
    """Byzantine scenario: adversary swaps the final decision step entirely.

    Even if they recompute step_hash for the new step, the Merkle root and the
    ML-DSA signature were computed over the ORIGINAL step hashes, so at least
    one of those two checks must fail.
    """
    r = sample_trace_started
    r.record_observation("Contract is standard")
    r.record_deduction("Clause X is enforceable")
    r.record_decision("Approve the contract")
    sealed = r.seal()

    # Adversary replaces the final decision content + recomputes step_hash
    last = sealed.steps[-1]
    last.content = "REJECT the contract"
    last.content_hash = last.hash_content(last.content)
    last.step_hash = last.compute_step_hash()
    # They try to patch final_chain_hash too
    sealed.final_chain_hash = last.step_hash

    result = TraceVerifier.verify(sealed)
    # Merkle root must still be over the ORIGINAL step hashes, so it mismatches,
    # and even if attacker updated merkle_root, the signature covers merkle_root.
    assert result.fully_verified is False
