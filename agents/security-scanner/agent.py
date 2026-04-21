"""Security Scanner -- finds classical crypto and attests eBPF sensors."""

from __future__ import annotations

import json
from pathlib import Path

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.identity.agent import AgentIdentity

from pqc_lint import Scanner
from pqc_ebpf_attestation import (
    BPFProgram,
    BPFProgramMetadata,
    BPFProgramType,
    BPFSigner,
    BPFVerifier,
)


IDENTITY_FILE = Path(__file__).parent / "identity.json"


def load_identity() -> AgentIdentity:
    data = json.loads(IDENTITY_FILE.read_text())
    return AgentIdentity.create(
        data["name"],
        capabilities=data["capabilities"],
        algorithm=SignatureAlgorithm.ML_DSA_87,
    )


def scan_source(root: str) -> tuple[int, int]:
    """Return (files_scanned, high_or_worse_findings)."""
    report = Scanner().scan_path(root)
    risky = sum(
        1 for f in report.findings if f.severity.order >= 3  # HIGH + CRITICAL
    )
    return report.files_scanned, risky


def attest_sensor(agent: AgentIdentity) -> bool:
    """Sign a stub eBPF sensor and verify the envelope."""
    program = BPFProgram(
        metadata=BPFProgramMetadata(
            name="pqc-syscall-monitor",
            program_type=BPFProgramType.TRACEPOINT,
            author=agent.did,
            version="1.0",
            attach_point="sys_enter_openat",
        ),
        bytecode=b"\x00" * 64,
    )
    program.bytecode_hash = BPFProgram.hash_bytecode(program.bytecode)
    program.bytecode_size = len(program.bytecode)
    signed = BPFSigner(agent).sign(program)
    return BPFVerifier.verify(signed).valid


def main() -> None:
    agent = load_identity()
    print(f"[agent] {agent.did}")

    files, risky = scan_source(str(Path(__file__).parent))
    print(f"[scan] files_scanned={files} high_plus_findings={risky}")

    ok = attest_sensor(agent)
    print(f"[ebpf] sensor attestation valid={ok}")


if __name__ == "__main__":
    main()
