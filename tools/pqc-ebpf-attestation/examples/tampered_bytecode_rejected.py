"""Show that mutating the bytecode of a SignedBPFProgram fails verification.

Run:
    python examples/tampered_bytecode_rejected.py
"""

from __future__ import annotations

from dataclasses import replace

from quantumshield.identity.agent import AgentIdentity

from pqc_ebpf_attestation import (
    BPFProgram,
    BPFProgramMetadata,
    BPFProgramType,
    BPFSigner,
    BPFVerifier,
)


def main() -> None:
    metadata = BPFProgramMetadata(
        name="xdp_filter_ddos",
        program_type=BPFProgramType.XDP,
        license="GPL",
        attach_point="eth0",
    )
    original_bytecode = b"\x7fELFGOOD" + b"\x00" * 256
    program = BPFProgram.from_bytes(metadata, original_bytecode)

    identity = AgentIdentity.create("bpf-signer")
    signed = BPFSigner(identity).sign(program)

    # Verify the untampered envelope first.
    clean = BPFVerifier.verify(signed)
    print(f"Clean envelope valid:       {clean.valid}")
    print(f"  signature_valid:           {clean.signature_valid}")
    print(f"  hash_consistent:           {clean.hash_consistent}")
    print()

    # Mutate the bytecode bytes AFTER signing. The stored hash no longer matches.
    tampered_program = replace(
        signed.program, bytecode=signed.program.bytecode[:-4] + b"EVIL"
    )
    tampered = replace(signed, program=tampered_program)

    result = BPFVerifier.verify(tampered)
    print(f"Tampered envelope valid:    {result.valid}")
    print(f"  signature_valid:           {result.signature_valid}")
    print(f"  hash_consistent:           {result.hash_consistent}")
    print(f"  error:                     {result.error}")


if __name__ == "__main__":
    main()
