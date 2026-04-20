"""Tests for BPFSigner / BPFVerifier / SignedBPFProgram."""

from __future__ import annotations

from dataclasses import replace

from pqc_ebpf_attestation import (
    BPFProgram,
    BPFVerifier,
    SignedBPFProgram,
)


def test_sign_populates_envelope_fields(signed_program) -> None:
    assert signed_program.signer_did.startswith("did:pqaid:")
    assert signed_program.algorithm.startswith("ML-DSA")
    assert len(signed_program.signature) > 0
    assert len(signed_program.public_key) > 0
    assert signed_program.signed_at  # iso string
    assert signed_program.program.bytecode_hash


def test_verify_success(signed_program) -> None:
    result = BPFVerifier.verify(signed_program)
    assert result.valid is True
    assert result.signature_valid is True
    assert result.hash_consistent is True
    assert result.error is None
    assert result.program_name == signed_program.program.metadata.name


def test_bytecode_tamper_detected(signed_program) -> None:
    # Mutate the bytecode after signing; stored hash no longer matches.
    tampered_program = replace(
        signed_program.program,
        bytecode=signed_program.program.bytecode + b"\x90",
    )
    tampered = replace(signed_program, program=tampered_program)
    result = BPFVerifier.verify(tampered)
    assert result.hash_consistent is False
    assert result.valid is False


def test_signature_tamper_detected(signed_program) -> None:
    # Flip a hex char in the signature.
    sig = signed_program.signature
    flipped = ("0" if sig[0] != "0" else "1") + sig[1:]
    tampered = replace(signed_program, signature=flipped)
    result = BPFVerifier.verify(tampered)
    assert result.signature_valid is False
    assert result.valid is False


def test_wrong_algorithm_rejected(signed_program) -> None:
    bogus = replace(signed_program, algorithm="RSA-4096")
    result = BPFVerifier.verify(bogus)
    assert result.valid is False
    assert result.error is not None
    assert "unknown algorithm" in result.error


def test_signed_program_roundtrip(signed_program) -> None:
    serialized = signed_program.to_dict(include_bytecode=True)
    restored = SignedBPFProgram.from_dict(serialized)
    assert restored.signer_did == signed_program.signer_did
    assert restored.algorithm == signed_program.algorithm
    assert restored.signature == signed_program.signature
    assert restored.public_key == signed_program.public_key
    assert restored.program.bytecode == signed_program.program.bytecode
    assert restored.program.bytecode_hash == signed_program.program.bytecode_hash

    # And the roundtripped envelope still verifies.
    result = BPFVerifier.verify(restored)
    assert result.valid is True


def test_verify_without_bytecode_is_signature_only(signed_program) -> None:
    """Envelopes stripped of bytecode should still verify via the signed manifest."""
    no_bytes = SignedBPFProgram.from_dict(signed_program.to_dict(include_bytecode=False))
    assert no_bytes.program.bytecode == b""
    result = BPFVerifier.verify(no_bytes)
    # hash_consistent defaults True when no bytecode is present to compare.
    assert result.hash_consistent is True
    assert result.signature_valid is True
    assert result.valid is True


def test_hash_helper_consistent(sample_bpf_metadata, sample_bytecode) -> None:
    prog = BPFProgram.from_bytes(sample_bpf_metadata, sample_bytecode)
    assert prog.bytecode_hash == BPFProgram.hash_bytecode(sample_bytecode)
