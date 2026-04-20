"""Tests for MBOMSigner and MBOMVerifier."""

from __future__ import annotations

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_mbom import MBOM, MBOMSigner, MBOMVerifier
from pqc_mbom.errors import SignatureVerificationError


def test_sign_populates_fields(sample_mbom: MBOM, creator_identity: AgentIdentity) -> None:
    signer = MBOMSigner(creator_identity)
    signer.sign(sample_mbom)
    assert sample_mbom.signer_did == creator_identity.did
    assert sample_mbom.algorithm
    assert sample_mbom.signature
    assert sample_mbom.public_key
    assert sample_mbom.signed_at


def test_verify_success(sample_mbom: MBOM, creator_identity: AgentIdentity) -> None:
    MBOMSigner(creator_identity).sign(sample_mbom)
    result = MBOMVerifier.verify(sample_mbom)
    assert result.valid
    assert result.signature_valid
    assert result.root_hash_valid
    assert result.error is None
    assert result.signer_did == creator_identity.did


def test_tamper_detection(sample_mbom: MBOM, creator_identity: AgentIdentity) -> None:
    MBOMSigner(creator_identity).sign(sample_mbom)
    # Tamper: change a component's name AFTER signing; the canonical bytes diverge.
    sample_mbom.components[0].name = "Evil-Replacement"
    result = MBOMVerifier.verify(sample_mbom)
    assert not result.valid
    # Either the signature OR the root check fails (both will, in fact).
    assert not (result.signature_valid and result.root_hash_valid)


def test_root_hash_mismatch_detection(sample_mbom: MBOM, creator_identity: AgentIdentity) -> None:
    MBOMSigner(creator_identity).sign(sample_mbom)
    # Overwrite stored root without recomputing - signature still matches the
    # canonical bytes (which include the bad root), but the recomputed root
    # will disagree.
    sample_mbom.components_root_hash = "f" * 64
    # re-sign with the wrong root baked in
    MBOMSigner(creator_identity).sign(sample_mbom)
    # Actually the signer always recomputes, so to force a mismatch we
    # mutate after signing without recompute:
    sample_mbom.components_root_hash = "0" * 64
    result = MBOMVerifier.verify(sample_mbom)
    assert not result.valid
    assert not result.root_hash_valid


def test_verify_or_raise(sample_mbom: MBOM, creator_identity: AgentIdentity) -> None:
    # Unsigned MBOM should raise
    with pytest.raises(SignatureVerificationError):
        MBOMVerifier.verify_or_raise(sample_mbom)

    MBOMSigner(creator_identity).sign(sample_mbom)
    # Signed valid MBOM returns result
    result = MBOMVerifier.verify_or_raise(sample_mbom)
    assert result.valid

    # Tamper then verify_or_raise raises
    sample_mbom.components[0].supplier = "Attacker"
    with pytest.raises(SignatureVerificationError):
        MBOMVerifier.verify_or_raise(sample_mbom)
