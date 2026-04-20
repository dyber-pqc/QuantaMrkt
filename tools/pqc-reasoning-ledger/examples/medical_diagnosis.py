"""7-step medical diagnosis reasoning trace with inclusion proof for the decision.

Shows how selective disclosure works: we can prove that the model's DECISION
step was part of a signed trace without revealing the other 6 steps.
"""

from __future__ import annotations

from quantumshield.identity.agent import AgentIdentity

from pqc_reasoning_ledger import (
    ReasoningProver,
    ReasoningRecorder,
    TraceVerifier,
)


def main() -> None:
    print("=" * 72)
    print("PQC Reasoning Ledger - Medical Diagnosis")
    print("=" * 72)

    identity = AgentIdentity.create("clinical-decision-signer")
    rec = ReasoningRecorder(identity)
    rec.begin_trace(
        model_did="did:pqaid:clinical-reasoner",
        model_version="3.2.1",
        task="differential-diagnosis",
        domain="medical",
        session_id="enc-2026-04-20-9127",
    )

    print("\n[1] Recording 7-step diagnostic reasoning...\n")

    rec.record_observation(
        "Patient (M, 58) presents with substernal chest pain radiating to left "
        "arm, onset 45 min ago, associated diaphoresis."
    )
    rec.record_observation(
        "Vitals: BP 148/92, HR 102, SpO2 96% RA, afebrile. ECG: 1 mm ST "
        "depression in V4-V6, no Q waves."
    )
    rec.record_retrieval(
        "Retrieved: ACC/AHA 2021 Guideline for the Evaluation and Diagnosis of "
        "Chest Pain; HEART score criteria."
    )
    rec.record_hypothesis(
        "Differential: NSTEMI > unstable angina > GERD/esophageal spasm > "
        "aortic dissection (less likely, no asymmetric pulses).",
        confidence=0.78,
    )
    rec.record_deduction(
        "HEART score: History 2 + ECG 1 + Age 1 + Risk 1 + Troponin pending = "
        "at least 5 (moderate-high risk). Cannot rule out ACS.",
        confidence=0.82,
    )
    rec.record_self_critique(
        "Troponin not yet resulted; decision cannot be deferred pending labs "
        "because 45-minute window already elapsed. Proceed with ACS workup."
    )
    decision = rec.record_decision(
        "IMMEDIATE ACTION: obtain serial troponins (0, 3h), start aspirin 325 mg "
        "chewed, admit to telemetry, cardiology consult. Re-evaluate for cath "
        "lab activation if troponin elevated or ECG evolves.",
        confidence=0.91,
    )

    print(f"  recorded {len(rec.trace.steps)} steps")
    print(f"  decision step_id: {decision.step_id}")

    print("\n[2] Sealing trace...\n")
    sealed = rec.seal()
    print(f"  trace_id:    {sealed.metadata.trace_id}")
    print(f"  merkle_root: {sealed.merkle_root[:32]}...")
    print(f"  algorithm:   {sealed.algorithm}")

    print("\n[3] Verifying sealed trace...\n")
    result = TraceVerifier.verify(sealed)
    print(f"  fully_verified: {result.fully_verified}")

    print("\n[4] Producing inclusion proof for the DECISION step only...\n")
    proof = ReasoningProver.prove_step(sealed, decision.step_id)
    print(f"  step proved:     {proof.step.kind.value} at index {proof.proof.index}")
    print(f"  proof siblings:  {len(proof.proof.siblings)} hashes")
    print(f"  tree_size:       {proof.proof.tree_size}")
    print(f"  root agrees:     {proof.proof.root == sealed.merkle_root}")

    ok = ReasoningProver.verify_proof(proof)
    status = "[OK]" if ok else "[FAIL]"
    print(f"\n  {status} decision step proven to be member of signed trace")
    print("         without revealing the other 6 steps.")


if __name__ == "__main__":
    main()
