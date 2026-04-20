"""Sign and verify a synthetic eBPF program round-trip.

Run:
    python examples/sign_and_verify.py
"""

from __future__ import annotations

import json

from quantumshield.identity.agent import AgentIdentity

from pqc_ebpf_attestation import (
    BPFProgram,
    BPFProgramMetadata,
    BPFProgramType,
    BPFSigner,
    BPFVerifier,
    SignedBPFProgram,
)


def main() -> None:
    # 1. Define the program metadata + some synthetic "bytecode".
    metadata = BPFProgramMetadata(
        name="trace_sys_enter_bpf",
        program_type=BPFProgramType.KPROBE,
        license="GPL",
        author="ops-team",
        description="Traces sys_enter_bpf to detect unauthorized loads.",
        version="1.0.0",
        kernel_min="5.15",
        attach_point="sys_enter_bpf",
    )
    bytecode = b"\x7fELF" + b"\x00" * 8 + bytes(range(256)) * 2

    program = BPFProgram.from_bytes(metadata, bytecode)
    print(f"Program:      {metadata.name}")
    print(f"Bytecode hash: {program.bytecode_hash}")
    print(f"Bytecode size: {program.bytecode_size} bytes")

    # 2. Sign with an ML-DSA identity.
    identity = AgentIdentity.create("bpf-signer", capabilities=["sign"])
    signer = BPFSigner(identity)
    signed = signer.sign(program)
    print(f"Signer DID:   {signed.signer_did}")
    print(f"Algorithm:    {signed.algorithm}")

    # 3. Serialize to JSON, then restore.
    payload = json.dumps(signed.to_dict(), indent=2)
    restored = SignedBPFProgram.from_dict(json.loads(payload))

    # 4. Verify the restored envelope.
    result = BPFVerifier.verify(restored)
    print(f"Verify valid: {result.valid}")
    print(f"Signature OK: {result.signature_valid}")
    print(f"Hash OK:      {result.hash_consistent}")
    assert result.valid


if __name__ == "__main__":
    main()
