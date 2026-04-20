"""Tests for LoadPolicy / PolicyRule."""

from __future__ import annotations

import pytest

from pqc_ebpf_attestation import (
    BPFProgram,
    BPFProgramType,
    LoadPolicy,
    PolicyDecision,
    PolicyDeniedError,
    PolicyRule,
    UntrustedSignerError,
)


def test_empty_policy_denies_everything(signed_program) -> None:
    policy = LoadPolicy()
    decision, reason = policy.evaluate(signed_program)
    assert decision == PolicyDecision.DENY
    assert "no rule" in reason


def test_rule_matches_by_program_type(signed_program) -> None:
    policy = LoadPolicy().add_rule(
        PolicyRule(
            program_types=(BPFProgramType.KPROBE,),
            allowed_signers=frozenset({signed_program.signer_did}),
        )
    )
    decision, _ = policy.evaluate(signed_program)
    assert decision == PolicyDecision.ALLOW

    # A rule that doesn't match the program_type falls through to default deny.
    policy2 = LoadPolicy().add_rule(
        PolicyRule(
            program_types=(BPFProgramType.XDP,),
            allowed_signers=frozenset({signed_program.signer_did}),
        )
    )
    decision2, reason2 = policy2.evaluate(signed_program)
    assert decision2 == PolicyDecision.DENY
    assert "no rule" in reason2


def test_size_cap_enforced(signer, sample_bpf_metadata, sample_bytecode) -> None:
    program = BPFProgram.from_bytes(sample_bpf_metadata, sample_bytecode)
    signed = signer.sign(program)
    policy = LoadPolicy().add_rule(
        PolicyRule(
            program_types=(BPFProgramType.KPROBE,),
            allowed_signers=frozenset({signed.signer_did}),
            max_bytecode_size=16,  # tiny cap to force denial
        )
    )
    decision, reason = policy.evaluate(signed)
    assert decision == PolicyDecision.DENY
    assert "exceeds cap" in reason


def test_allow_list_filters_signers(
    signer, untrusted_identity, sample_bpf_metadata, sample_bytecode
) -> None:
    from pqc_ebpf_attestation import BPFSigner

    # Sign the same program with an untrusted identity.
    untrusted_signer = BPFSigner(untrusted_identity)
    untrusted_signed = untrusted_signer.sign(
        BPFProgram.from_bytes(sample_bpf_metadata, sample_bytecode)
    )

    # Allow-list only contains the trusted signer.
    policy = LoadPolicy().add_rule(
        PolicyRule(
            program_types=(BPFProgramType.KPROBE,),
            allowed_signers=frozenset({signer.identity.did}),
        )
    )
    decision, reason = policy.evaluate(untrusted_signed)
    assert decision == PolicyDecision.DENY
    assert "not in allow-list" in reason


def test_untrusted_signer_raises_specific_error(
    signer, untrusted_identity, sample_bpf_metadata, sample_bytecode
) -> None:
    from pqc_ebpf_attestation import BPFSigner

    untrusted_signed = BPFSigner(untrusted_identity).sign(
        BPFProgram.from_bytes(sample_bpf_metadata, sample_bytecode)
    )

    policy = LoadPolicy().add_rule(
        PolicyRule(
            program_types=(BPFProgramType.KPROBE,),
            allowed_signers=frozenset({signer.identity.did}),
        )
    )
    with pytest.raises(UntrustedSignerError):
        policy.enforce(untrusted_signed)


def test_general_deny_raises_policy_denied(signed_program) -> None:
    policy = LoadPolicy()  # no rules => default deny, but not allow-list related
    with pytest.raises(PolicyDeniedError):
        policy.enforce(signed_program)


def test_multiple_rules_first_match_wins(signed_program) -> None:
    # First rule matches KPROBE with allow-list containing the signer - ALLOW.
    # Second rule also matches KPROBE but with an empty allow-list of a different
    # signer - it would deny, but should never be consulted.
    policy = LoadPolicy()
    policy.add_rule(
        PolicyRule(
            program_types=(BPFProgramType.KPROBE,),
            allowed_signers=frozenset({signed_program.signer_did}),
        )
    )
    policy.add_rule(
        PolicyRule(
            program_types=(BPFProgramType.KPROBE,),
            allowed_signers=frozenset({"did:pqaid:not-this-one"}),
        )
    )
    decision, _ = policy.evaluate(signed_program)
    assert decision == PolicyDecision.ALLOW


