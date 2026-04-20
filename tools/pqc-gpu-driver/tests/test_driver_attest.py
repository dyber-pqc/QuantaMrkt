"""Tests for DriverAttester / DriverAttestationVerifier."""

from __future__ import annotations

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_gpu_driver import (
    DriverAttestationError,
    DriverAttestationVerifier,
    DriverAttester,
    DriverModule,
)


def test_attest_populates_signature_fields(
    attester: DriverAttester, sample_module: DriverModule
) -> None:
    att = attester.attest(sample_module)
    assert att.module == sample_module
    assert att.signer_did == attester.identity.did
    assert att.algorithm == attester.identity.signing_keypair.algorithm.value
    assert att.signature and len(att.signature) > 0
    assert att.public_key and len(att.public_key) > 0
    assert att.signed_at.endswith("+00:00")


def test_verify_valid_attestation(
    attester: DriverAttester,
    sample_module: DriverModule,
    sample_module_bytes: bytes,
) -> None:
    att = attester.attest(sample_module)
    verifier = DriverAttestationVerifier()
    result = verifier.verify(att, actual_module_bytes=sample_module_bytes)
    assert result.valid is True
    assert result.error is None
    assert result.signer_did == attester.identity.did


def test_verify_detects_hash_tamper(
    attester: DriverAttester, sample_module: DriverModule
) -> None:
    att = attester.attest(sample_module)
    verifier = DriverAttestationVerifier()
    # Pass DIFFERENT bytes than what was attested - verifier must reject.
    result = verifier.verify(att, actual_module_bytes=b"totally different bytes")
    assert result.valid is False
    assert "module hash mismatch" in (result.error or "")


def test_trusted_signers_allowlist_filters_untrusted(
    trusted_identity: AgentIdentity,
    untrusted_identity: AgentIdentity,
    sample_module: DriverModule,
) -> None:
    trusted_att = DriverAttester(trusted_identity).attest(sample_module)
    untrusted_att = DriverAttester(untrusted_identity).attest(sample_module)

    verifier = DriverAttestationVerifier(trusted_signers={trusted_identity.did})

    good = verifier.verify(trusted_att)
    assert good.valid is True
    assert good.trusted is True

    bad = verifier.verify(untrusted_att)
    assert bad.valid is False
    assert bad.trusted is False
    assert "not in trusted set" in (bad.error or "")


def test_signature_tamper_detected(
    attester: DriverAttester, sample_module: DriverModule
) -> None:
    att = attester.attest(sample_module)
    # Flip one hex nibble in the signature.
    att.signature = ("0" if att.signature[0] != "0" else "1") + att.signature[1:]
    verifier = DriverAttestationVerifier()
    result = verifier.verify(att)
    assert result.valid is False
    assert result.error is not None


def test_missing_signature_rejected(sample_module: DriverModule) -> None:
    from pqc_gpu_driver import DriverAttestation

    att = DriverAttestation(module=sample_module)
    verifier = DriverAttestationVerifier()
    result = verifier.verify(att)
    assert result.valid is False
    assert "missing signature fields" in (result.error or "")


def test_verify_or_raise_raises_on_invalid(
    attester: DriverAttester, sample_module: DriverModule
) -> None:
    att = attester.attest(sample_module)
    att.signature = ""  # invalidate
    verifier = DriverAttestationVerifier()
    with pytest.raises(DriverAttestationError):
        verifier.verify_or_raise(att)
