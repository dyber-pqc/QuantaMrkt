"""Tests for UpdateSigner."""

from __future__ import annotations

from quantumshield.identity.agent import AgentIdentity

from pqc_federated_learning import (
    ClientUpdate,
    ClientUpdateMetadata,
    GradientTensor,
    UpdateSigner,
)


def _make_update(did: str = "did:pqaid:abc") -> ClientUpdate:
    meta = ClientUpdateMetadata(
        client_did=did,
        round_id="r1",
        model_id="m1",
        num_samples=10,
    )
    tensors = [GradientTensor(name="w", shape=(2,), values=(1.0, 2.0))]
    return ClientUpdate.create(meta, tensors)


def test_sign_populates_fields(client_a_identity: AgentIdentity) -> None:
    u = _make_update(client_a_identity.did)
    signed = UpdateSigner(client_a_identity).sign(u)
    assert signed.signer_did == client_a_identity.did
    assert signed.algorithm == client_a_identity.signing_keypair.algorithm.value
    assert signed.signature != ""
    assert signed.public_key != ""
    assert signed.signed_at != ""


def test_verify_success(client_a_identity: AgentIdentity) -> None:
    u = _make_update(client_a_identity.did)
    signed = UpdateSigner(client_a_identity).sign(u)
    result = UpdateSigner.verify(signed)
    assert result.valid is True
    assert result.content_hash_ok is True
    assert result.signature_ok is True
    assert result.error is None


def test_tamper_detection_on_values(client_a_identity: AgentIdentity) -> None:
    u = _make_update(client_a_identity.did)
    signed = UpdateSigner(client_a_identity).sign(u)
    # Tamper: replace a tensor with different values. Signature stays, hash mismatches.
    signed.tensors = [GradientTensor(name="w", shape=(2,), values=(9.0, 9.0))]
    result = UpdateSigner.verify(signed)
    assert result.valid is False
    # Hash no longer matches, and signature no longer verifies the tampered bytes
    assert result.content_hash_ok is False or result.signature_ok is False


def test_wrong_public_key_fails(
    client_a_identity: AgentIdentity, attacker_identity: AgentIdentity
) -> None:
    u = _make_update(client_a_identity.did)
    signed = UpdateSigner(client_a_identity).sign(u)
    # Swap in attacker's public key
    signed.public_key = attacker_identity.signing_keypair.public_key.hex()
    result = UpdateSigner.verify(signed)
    assert result.valid is False
    assert result.signature_ok is False


def test_missing_signature_fields_invalid() -> None:
    u = _make_update()
    # No sign() called - signature fields empty
    result = UpdateSigner.verify(u)
    assert result.valid is False
    assert result.error == "missing signature fields"
