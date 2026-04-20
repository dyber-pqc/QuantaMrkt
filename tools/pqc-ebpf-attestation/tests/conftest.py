"""Shared pytest fixtures for pqc-ebpf-attestation tests."""

from __future__ import annotations

from typing import Callable

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_ebpf_attestation import (
    BPFProgram,
    BPFProgramMetadata,
    BPFProgramType,
    BPFSigner,
    SignedBPFProgram,
)


@pytest.fixture
def signer_identity() -> AgentIdentity:
    return AgentIdentity.create("trusted-bpf-signer", capabilities=["sign"])


@pytest.fixture
def untrusted_identity() -> AgentIdentity:
    return AgentIdentity.create("untrusted-bpf-signer", capabilities=["sign"])


@pytest.fixture
def signer(signer_identity: AgentIdentity) -> BPFSigner:
    return BPFSigner(signer_identity)


@pytest.fixture
def sample_bpf_metadata() -> BPFProgramMetadata:
    return BPFProgramMetadata(
        name="trace_sys_enter_read",
        program_type=BPFProgramType.KPROBE,
        license="GPL",
        author="ops-team",
        description="Traces sys_enter_read for latency histograms.",
        version="1.0.0",
        kernel_min="5.15",
        attach_point="sys_enter_read",
    )


@pytest.fixture
def sample_bytecode() -> bytes:
    # Non-trivial bytes simulating a small ELF-like payload.
    # Not real BPF bytecode - just enough to exercise hashing and signing.
    header = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    instructions = bytes(range(256)) * 4  # 1024 bytes of deterministic content
    return header + instructions


@pytest.fixture
def signed_program(
    signer: BPFSigner,
    sample_bpf_metadata: BPFProgramMetadata,
    sample_bytecode: bytes,
) -> SignedBPFProgram:
    program = BPFProgram.from_bytes(sample_bpf_metadata, sample_bytecode)
    return signer.sign(program)


@pytest.fixture
def signed_program_factory(
    signer: BPFSigner,
) -> Callable[[BPFProgramMetadata, bytes], SignedBPFProgram]:
    """Factory that builds a SignedBPFProgram from metadata + bytes."""

    def _make(metadata: BPFProgramMetadata, bytecode: bytes) -> SignedBPFProgram:
        program = BPFProgram.from_bytes(metadata, bytecode)
        return signer.sign(program)

    return _make
