"""End-to-end integration tests for pqc-ebpf-attestation."""

from __future__ import annotations

from dataclasses import replace

from pqc_ebpf_attestation import (
    AttestationLog,
    BPFProgram,
    BPFProgramType,
    BPFSigner,
    LoadPolicy,
    PolicyDecision,
    PolicyRule,
)


def test_full_sign_enforce_and_log(
    signer, untrusted_identity, sample_bpf_metadata, sample_bytecode
) -> None:
    # 1. Sign a program with a trusted identity.
    program = BPFProgram.from_bytes(sample_bpf_metadata, sample_bytecode)
    signed = signer.sign(program)

    # 2. Build a policy that only allows the trusted signer for KPROBE programs.
    policy = LoadPolicy().add_rule(
        PolicyRule(
            program_types=(BPFProgramType.KPROBE,),
            allowed_signers=frozenset({signer.identity.did}),
        )
    )

    # 3. Trusted signed program is allowed and logged.
    log = AttestationLog()
    decision, reason = policy.evaluate(signed)
    log.log(signed, decision, reason)
    assert decision == PolicyDecision.ALLOW

    # 4. Untrusted signer is denied and logged.
    untrusted_signer = BPFSigner(untrusted_identity)
    untrusted_signed = untrusted_signer.sign(program)
    decision2, reason2 = policy.evaluate(untrusted_signed)
    log.log(untrusted_signed, decision2, reason2)
    assert decision2 == PolicyDecision.DENY
    assert "not in allow-list" in reason2

    # 5. Audit log contains exactly two entries.
    entries = log.entries()
    assert len(entries) == 2
    decisions = {e.decision for e in entries}
    assert decisions == {"allow", "deny"}


def test_tampered_bytecode_rejected_and_logged(
    signer, sample_bpf_metadata, sample_bytecode
) -> None:
    program = BPFProgram.from_bytes(sample_bpf_metadata, sample_bytecode)
    signed = signer.sign(program)

    # Tamper with the bytecode after signing.
    tampered_program = replace(
        signed.program, bytecode=signed.program.bytecode + b"\xde\xad\xbe\xef"
    )
    tampered = replace(signed, program=tampered_program)

    policy = LoadPolicy().add_rule(
        PolicyRule(
            program_types=(BPFProgramType.KPROBE,),
            allowed_signers=frozenset({signer.identity.did}),
        )
    )
    log = AttestationLog()
    decision, reason = policy.evaluate(tampered)
    log.log(tampered, decision, reason)

    assert decision == PolicyDecision.DENY
    assert "hash" in reason.lower() or "signature" in reason.lower()
    entries = log.entries(decision="deny")
    assert len(entries) == 1
    assert entries[0].program_name == sample_bpf_metadata.name
