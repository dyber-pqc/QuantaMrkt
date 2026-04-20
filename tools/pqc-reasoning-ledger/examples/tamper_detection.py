"""Tamper-detection demo: build a trace, seal, tamper, show verification fails."""

from __future__ import annotations

from quantumshield.identity.agent import AgentIdentity

from pqc_reasoning_ledger import ReasoningRecorder, TraceVerifier


def main() -> None:
    print("=" * 72)
    print("PQC Reasoning Ledger - Tamper Detection Demo")
    print("=" * 72)

    identity = AgentIdentity.create("demo-signer")
    rec = ReasoningRecorder(identity)
    rec.begin_trace(
        model_did="did:pqaid:demo-model",
        model_version="1.0.0",
        task="loan-underwriting",
        domain="finance",
    )

    rec.record_observation("Applicant FICO score: 742; DTI ratio: 0.31")
    rec.record_retrieval("Underwriting guideline v2.8, section 3.2 (prime credit)")
    rec.record_hypothesis(
        "Applicant meets prime-credit thresholds for the 30-year fixed product"
    )
    tampered_target = rec.record_deduction(
        "FICO 742 >= 740 prime cutoff, DTI 0.31 < 0.36 cap -> prime eligible",
        confidence=0.93,
    )
    rec.record_decision("APPROVE at posted prime rate")

    print(f"\n[1] Built 5-step trace; target step_id = {tampered_target.step_id[-16:]}")

    sealed = rec.seal()

    print("\n[2] Verifying sealed trace as-delivered...\n")
    pristine = TraceVerifier.verify(sealed)
    print(f"  signature_valid:   {pristine.signature_valid}")
    print(f"  chain_intact:      {pristine.chain_intact}")
    print(f"  merkle_root_valid: {pristine.merkle_root_valid}")
    print(f"  fully_verified:    {pristine.fully_verified}   <-- should be True")

    print("\n[3] Adversary flips a single byte in step 4 content_hash...\n")
    step_idx = 3  # zero-based index of the deduction step
    original = sealed.steps[step_idx].content_hash
    flipped = ("0" if original[0] != "0" else "f") + original[1:]
    sealed.steps[step_idx].content_hash = flipped
    print(f"  before: {original[:32]}...")
    print(f"  after:  {flipped[:32]}...")

    print("\n[4] Verifying tampered trace...\n")
    tampered = TraceVerifier.verify(sealed)
    print(f"  signature_valid:   {tampered.signature_valid}")
    print(f"  chain_intact:      {tampered.chain_intact}    <-- now False")
    print(f"  merkle_root_valid: {tampered.merkle_root_valid}")
    print(f"  fully_verified:    {tampered.fully_verified}   <-- should be False")
    print(f"  error:             {tampered.error}")

    if not tampered.fully_verified:
        print("\n  [OK] a single flipped byte broke the chain -- tamper detected.")
    else:
        print("\n  [FAIL] unexpected: tamper went undetected")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
