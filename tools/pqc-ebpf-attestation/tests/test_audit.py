"""Tests for AttestationLog."""

from __future__ import annotations

from pqc_ebpf_attestation import (
    AttestationLog,
    BPFProgram,
    BPFProgramMetadata,
    BPFProgramType,
    BPFSigner,
    PolicyDecision,
)


def test_log_entry_captures_fields(signed_program) -> None:
    log = AttestationLog()
    entry = log.log(signed_program, PolicyDecision.ALLOW, "ok", actor="ops@example")
    assert entry.program_name == signed_program.program.metadata.name
    assert entry.program_type == signed_program.program.metadata.program_type.value
    assert entry.bytecode_hash == signed_program.program.bytecode_hash
    assert entry.signer_did == signed_program.signer_did
    assert entry.decision == "allow"
    assert entry.reason == "ok"
    assert entry.actor == "ops@example"
    assert entry.timestamp
    assert len(log) == 1


def test_filter_by_decision(signed_program) -> None:
    log = AttestationLog()
    log.log(signed_program, PolicyDecision.ALLOW, "allowed")
    log.log(signed_program, PolicyDecision.DENY, "bad")
    log.log(signed_program, PolicyDecision.DENY, "worse")
    allows = log.entries(decision="allow")
    denies = log.entries(decision="deny")
    assert len(allows) == 1
    assert len(denies) == 2
    assert all(e.decision == "deny" for e in denies)


def test_filter_by_signer_did(signer_identity, untrusted_identity, sample_bpf_metadata) -> None:
    trusted_signed = BPFSigner(signer_identity).sign(
        BPFProgram.from_bytes(sample_bpf_metadata, b"trusted-bytes")
    )
    untrusted_signed = BPFSigner(untrusted_identity).sign(
        BPFProgram.from_bytes(sample_bpf_metadata, b"untrusted-bytes")
    )
    log = AttestationLog()
    log.log(trusted_signed, PolicyDecision.ALLOW, "ok")
    log.log(untrusted_signed, PolicyDecision.DENY, "no")
    log.log(trusted_signed, PolicyDecision.ALLOW, "ok")

    only_trusted = log.entries(signer_did=signer_identity.did)
    only_untrusted = log.entries(signer_did=untrusted_identity.did)
    assert len(only_trusted) == 2
    assert len(only_untrusted) == 1
    assert all(e.signer_did == signer_identity.did for e in only_trusted)


def test_max_entries_rotation(signer, sample_bpf_metadata) -> None:
    # Create several distinct signed programs to fill the log past its cap.
    log = AttestationLog(max_entries=3)
    for i in range(10):
        meta = BPFProgramMetadata(
            name=f"prog-{i}",
            program_type=BPFProgramType.KPROBE,
        )
        signed = signer.sign(BPFProgram.from_bytes(meta, f"bytes-{i}".encode()))
        log.log(signed, PolicyDecision.ALLOW, f"entry-{i}")
    assert len(log) == 3
    # Most recent first, so the first entry should be prog-9.
    recent = log.entries()
    assert recent[0].program_name == "prog-9"
    assert recent[-1].program_name == "prog-7"
