"""6-step legal contract review reasoning trace.

Demonstrates a realistic chain-of-thought for a legal advisor AI:
observation -> hypothesis -> retrieval -> deduction -> self-critique -> decision
"""

from __future__ import annotations

from quantumshield.identity.agent import AgentIdentity

from pqc_reasoning_ledger import ReasoningRecorder, TraceVerifier


def main() -> None:
    print("=" * 72)
    print("PQC Reasoning Ledger - Legal Contract Review")
    print("=" * 72)

    identity = AgentIdentity.create("legal-advisor-signer")
    rec = ReasoningRecorder(identity)
    rec.begin_trace(
        model_did="did:pqaid:gpt-legal-advisor",
        model_version="2.1.0",
        task="contract-review",
        domain="legal",
        actor_did="did:pqaid:acme-corp-counsel",
        session_id="sess-20260420-001",
    )

    print("\n[1] Recording reasoning steps during inference...\n")

    s1 = rec.record_observation(
        "Contract section 7.2 contains a liquidated damages clause "
        "with a $1,000,000 cap per breach."
    )
    print(f"  [+] step 1 ({s1.kind.value}): {s1.step_id[-12:]}")

    s2 = rec.record_retrieval(
        "Retrieved: Truck Rent-A-Center v. Puritan Farms 2nd, 41 N.Y.2d 420 (1977); "
        "NY CPLR 3215; Restatement (Second) of Contracts S 356."
    )
    print(f"  [+] step 2 ({s2.kind.value}): {s2.step_id[-12:]}")

    s3 = rec.record_hypothesis(
        "Under NY law, a liquidated damages clause is enforceable if (a) actual "
        "damages are difficult to ascertain at contract formation, and (b) the "
        "stipulated sum is a reasonable estimate of probable loss.",
        confidence=0.85,
    )
    print(f"  [+] step 3 ({s3.kind.value}): {s3.step_id[-12:]}")

    s4 = rec.record_deduction(
        "Projected actual damages from breach in this sector: $900k - $1.3M. "
        "The $1M cap is within the reasonable-estimate range, so section 7.2 "
        "is likely enforceable.",
        confidence=0.80,
    )
    print(f"  [+] step 4 ({s4.kind.value}): {s4.step_id[-12:]}")

    s5 = rec.record_self_critique(
        "I should also verify the clause does not function as a penalty: the cap "
        "is below the high end of projected damages, which supports enforceability "
        "rather than undermining it."
    )
    print(f"  [+] step 5 ({s5.kind.value}): {s5.step_id[-12:]}")

    s6 = rec.record_decision(
        "RECOMMEND SIGNING with addition of a force-majeure carve-out in section "
        "7.2(b) to address supply-chain risks. Liquidated damages provision as "
        "drafted is likely enforceable under NY law.",
        confidence=0.88,
    )
    print(f"  [+] step 6 ({s6.kind.value}): {s6.step_id[-12:]}")

    print("\n[2] Sealing trace with ML-DSA-65...\n")
    sealed = rec.seal()
    print(f"  trace_id:         {sealed.metadata.trace_id}")
    print(f"  step_count:       {sealed.step_count}")
    print(f"  final_chain_hash: {sealed.final_chain_hash[:32]}...")
    print(f"  merkle_root:      {sealed.merkle_root[:32]}...")
    print(f"  algorithm:        {sealed.algorithm}")
    print(f"  signer_did:       {sealed.signer_did}")
    print(f"  signature bytes:  {len(sealed.signature) // 2}")

    print("\n[3] Independent verification...\n")
    result = TraceVerifier.verify(sealed)
    print(f"  signature_valid:   {result.signature_valid}")
    print(f"  chain_intact:      {result.chain_intact}")
    print(f"  merkle_root_valid: {result.merkle_root_valid}")
    print(f"  fully_verified:    {result.fully_verified}")
    status = "[OK]" if result.fully_verified else "[FAIL]"
    print(f"\n  {status} legally defensible reasoning trail produced.")


if __name__ == "__main__":
    main()
