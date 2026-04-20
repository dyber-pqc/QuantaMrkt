"""Tests for DeviceAttester + DeviceAttestation."""

from __future__ import annotations

import pytest

from pqc_enclave_sdk import (
    AttestationError,
    DeviceAttester,
)


def test_attest_sets_signer_did_algorithm_signature(signer_identity) -> None:
    attester = DeviceAttester(
        identity=signer_identity,
        device_id="iphone-1",
        device_model="iphone-15-pro",
        enclave_vendor="apple-se",
    )
    att = attester.attest(
        artifact_id="urn:pqc-enclave-art:abc",
        content_hash="cafebabe",
    )
    assert att.signer_did == signer_identity.did
    assert att.algorithm == signer_identity.signing_keypair.algorithm.value
    assert att.signature
    assert att.public_key


def test_verify_valid_attestation(signer_identity) -> None:
    attester = DeviceAttester(
        identity=signer_identity,
        device_id="pixel-8",
        device_model="pixel-8",
        enclave_vendor="android-strongbox",
    )
    att = attester.attest(
        artifact_id="urn:pqc-enclave-art:def",
        content_hash="deadbeef",
    )
    assert DeviceAttester.verify(att) is True


def test_tamper_signature_detected(signer_identity) -> None:
    attester = DeviceAttester(
        identity=signer_identity,
        device_id="d",
        device_model="m",
        enclave_vendor="in-memory",
    )
    att = attester.attest(
        artifact_id="urn:pqc-enclave-art:tamper",
        content_hash="1234",
    )
    # Flip a hex nibble in the signature.
    tampered = bytearray.fromhex(att.signature)
    tampered[0] ^= 0x01
    att.signature = tampered.hex()
    assert DeviceAttester.verify(att) is False


def test_verify_or_raise_raises_on_invalid(signer_identity) -> None:
    attester = DeviceAttester(
        identity=signer_identity,
        device_id="d",
        device_model="m",
        enclave_vendor="in-memory",
    )
    att = attester.attest(
        artifact_id="urn:pqc-enclave-art:invalid",
        content_hash="5678",
    )
    # Replace the signature with all-zeros of the same length - invalid bytes
    # but a valid hex shape so verify() returns False rather than raising.
    att.signature = "00" * (len(att.signature) // 2)
    with pytest.raises(AttestationError):
        DeviceAttester.verify_or_raise(att)
