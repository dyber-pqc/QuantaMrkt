"""Tests for BPFProgram / BPFProgramMetadata."""

from __future__ import annotations

import base64

from pqc_ebpf_attestation import BPFProgram, BPFProgramMetadata, BPFProgramType


def test_hash_bytecode_is_deterministic() -> None:
    data = b"some eBPF ELF bytes"
    h1 = BPFProgram.hash_bytecode(data)
    h2 = BPFProgram.hash_bytecode(data)
    assert h1 == h2
    assert len(h1) == 64  # sha3-256 hex


def test_hash_differs_with_content() -> None:
    h1 = BPFProgram.hash_bytecode(b"payload-a")
    h2 = BPFProgram.hash_bytecode(b"payload-b")
    assert h1 != h2


def test_from_bytes_and_from_file(tmp_path, sample_bpf_metadata, sample_bytecode) -> None:
    prog_bytes = BPFProgram.from_bytes(sample_bpf_metadata, sample_bytecode)
    assert prog_bytes.bytecode == sample_bytecode
    assert prog_bytes.bytecode_size == len(sample_bytecode)
    assert prog_bytes.bytecode_hash == BPFProgram.hash_bytecode(sample_bytecode)

    bpf_path = tmp_path / "program.bpf.o"
    bpf_path.write_bytes(sample_bytecode)
    prog_file = BPFProgram.from_file(sample_bpf_metadata, str(bpf_path))
    assert prog_file.bytecode == sample_bytecode
    assert prog_file.bytecode_hash == prog_bytes.bytecode_hash


def test_canonical_manifest_bytes_is_deterministic(sample_bpf_metadata, sample_bytecode) -> None:
    prog_a = BPFProgram.from_bytes(sample_bpf_metadata, sample_bytecode)
    prog_b = BPFProgram.from_bytes(sample_bpf_metadata, sample_bytecode)
    assert prog_a.canonical_manifest_bytes() == prog_b.canonical_manifest_bytes()

    # Changing the bytecode also changes the canonical manifest (via hash+size).
    prog_c = BPFProgram.from_bytes(sample_bpf_metadata, sample_bytecode + b"\x00")
    assert prog_a.canonical_manifest_bytes() != prog_c.canonical_manifest_bytes()


def test_to_dict_with_and_without_bytecode(sample_bpf_metadata, sample_bytecode) -> None:
    prog = BPFProgram.from_bytes(sample_bpf_metadata, sample_bytecode)

    d_noby = prog.to_dict(include_bytecode=False)
    assert "bytecode_base64" not in d_noby
    assert d_noby["bytecode_hash"] == prog.bytecode_hash
    assert d_noby["metadata"]["program_type"] == BPFProgramType.KPROBE.value

    d_by = prog.to_dict(include_bytecode=True)
    assert "bytecode_base64" in d_by
    assert base64.b64decode(d_by["bytecode_base64"]) == sample_bytecode


def test_metadata_to_dict_uses_string_enum() -> None:
    meta = BPFProgramMetadata(name="x", program_type=BPFProgramType.XDP)
    assert meta.to_dict()["program_type"] == "xdp"
