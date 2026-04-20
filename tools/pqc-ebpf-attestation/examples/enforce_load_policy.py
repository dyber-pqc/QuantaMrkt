"""Enforce a LoadPolicy across trusted and untrusted signers.

Run:
    python examples/enforce_load_policy.py
"""

from __future__ import annotations

from quantumshield.identity.agent import AgentIdentity

from pqc_ebpf_attestation import (
    AttestationLog,
    BPFProgram,
    BPFProgramMetadata,
    BPFProgramType,
    BPFSigner,
    LoadPolicy,
    PolicyRule,
)


def main() -> None:
    # Three signing identities. Only the first two are on the allow-list.
    trusted_a = AgentIdentity.create("trusted-signer-a", capabilities=["sign"])
    trusted_b = AgentIdentity.create("trusted-signer-b", capabilities=["sign"])
    untrusted = AgentIdentity.create("rogue-signer", capabilities=["sign"])

    # The program itself is identical bytecode; each identity signs it independently.
    metadata = BPFProgramMetadata(
        name="kprobe_do_sys_openat2",
        program_type=BPFProgramType.KPROBE,
        license="GPL",
        author="ops",
        attach_point="do_sys_openat2",
    )
    bytecode = b"\x7fELF" + b"\xaa" * 512

    program = BPFProgram.from_bytes(metadata, bytecode)
    signed_by = {
        "trusted-a": BPFSigner(trusted_a).sign(program),
        "trusted-b": BPFSigner(trusted_b).sign(program),
        "untrusted": BPFSigner(untrusted).sign(program),
    }

    # Policy: KPROBE programs must be signed by trusted_a or trusted_b.
    policy = LoadPolicy().add_rule(
        PolicyRule(
            program_types=(BPFProgramType.KPROBE,),
            allowed_signers=frozenset({trusted_a.did, trusted_b.did}),
        )
    )

    log = AttestationLog()
    print(f"{'signer':<12}  {'decision':<6}  reason")
    print("-" * 72)
    for label, signed in signed_by.items():
        decision, reason = policy.evaluate(signed)
        log.log(signed, decision, reason, actor=f"load:{label}")
        print(f"{label:<12}  {decision.value:<6}  {reason}")

    print()
    print("Audit log (most recent first):")
    for entry in log.entries():
        short_did = entry.signer_did.split(":")[-1][:12]
        print(f"  {entry.timestamp}  {entry.decision:<5}  signer={short_did}  {entry.reason}")


if __name__ == "__main__":
    main()
