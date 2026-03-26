"""Tests for core cryptographic primitives."""

import warnings

import pytest

from quantumshield.core.algorithms import KEMAlgorithm, SignatureAlgorithm
from quantumshield.core.keys import (
    KEMKeypair,
    SigningKeypair,
    _HAS_PQC,
    _STUB_KEM_SIZES,
    _STUB_SIG_SIZES,
    generate_kem_keypair,
    generate_signing_keypair,
    has_pqc,
)
from quantumshield.core.signatures import sign, verify


# ---------------------------------------------------------------------------
# Key generation (works in both stub and real mode)
# ---------------------------------------------------------------------------


def test_generate_signing_keypair_default():
    """Signing keypair generation returns correct types with default algorithm."""
    keypair = generate_signing_keypair()
    assert isinstance(keypair, SigningKeypair)
    assert isinstance(keypair.public_key, bytes)
    assert isinstance(keypair.private_key, bytes)
    assert keypair.algorithm == SignatureAlgorithm.ML_DSA_65
    assert len(keypair.public_key) > 0
    assert len(keypair.private_key) > 0


def test_generate_signing_keypair_all_algorithms():
    """Signing keypair generation works for each algorithm variant."""
    for algo in SignatureAlgorithm:
        keypair = generate_signing_keypair(algo)
        assert keypair.algorithm == algo
        assert len(keypair.public_key) > 0
        assert len(keypair.private_key) > 0


def test_generate_kem_keypair_default():
    """KEM keypair generation returns correct types with default algorithm."""
    keypair = generate_kem_keypair()
    assert isinstance(keypair, KEMKeypair)
    assert isinstance(keypair.public_key, bytes)
    assert isinstance(keypair.private_key, bytes)
    assert keypair.algorithm == KEMAlgorithm.ML_KEM_768
    assert len(keypair.public_key) > 0
    assert len(keypair.private_key) > 0


def test_generate_kem_keypair_all_algorithms():
    """KEM keypair generation works for each algorithm variant."""
    for algo in KEMAlgorithm:
        keypair = generate_kem_keypair(algo)
        assert keypair.algorithm == algo
        assert len(keypair.public_key) > 0
        assert len(keypair.private_key) > 0


def test_keypairs_are_unique():
    """Each keypair generation produces unique keys."""
    kp1 = generate_signing_keypair()
    kp2 = generate_signing_keypair()
    assert kp1.public_key != kp2.public_key
    assert kp1.private_key != kp2.private_key


def test_has_pqc_returns_bool():
    """has_pqc() returns a boolean."""
    assert isinstance(has_pqc(), bool)


# ---------------------------------------------------------------------------
# Stub-mode specific tests (only run when liboqs is NOT installed)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_HAS_PQC, reason="liboqs is installed; stub tests not applicable")
class TestStubMode:
    """Tests that verify correct stub behaviour when liboqs is absent."""

    def test_stub_signing_key_sizes(self):
        """Stub keypairs match the approximate real key sizes."""
        for algo, (pk_size, sk_size) in _STUB_SIG_SIZES.items():
            kp = generate_signing_keypair(algo)
            assert len(kp.public_key) == pk_size
            assert len(kp.private_key) == sk_size

    def test_stub_kem_key_sizes(self):
        """Stub KEM keypairs match the approximate real key sizes."""
        for algo, (pk_size, sk_size) in _STUB_KEM_SIZES.items():
            kp = generate_kem_keypair(algo)
            assert len(kp.public_key) == pk_size
            assert len(kp.private_key) == sk_size

    def test_stub_sign_returns_bytes(self):
        """Stub sign() returns bytes of nonzero length."""
        kp = generate_signing_keypair()
        sig = sign(b"hello", kp)
        assert isinstance(sig, bytes)
        assert len(sig) > 0

    def test_stub_verify_returns_true(self):
        """Stub verify() always returns True."""
        assert verify(b"hello", b"\x00" * 64, b"\x00" * 32, SignatureAlgorithm.ML_DSA_65) is True


# ---------------------------------------------------------------------------
# Real PQC tests (only run when liboqs IS installed)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _HAS_PQC, reason="liboqs not installed; skipping real PQC tests")
class TestRealPQC:
    """Tests that exercise the real liboqs PQC backend."""

    def test_real_sign_and_verify(self):
        """A real signature round-trips through sign + verify."""
        kp = generate_signing_keypair(SignatureAlgorithm.ML_DSA_65)
        message = b"hello quantum world"
        sig = sign(message, kp)
        assert isinstance(sig, bytes)
        assert len(sig) > 0
        assert verify(message, sig, kp.public_key, kp.algorithm) is True

    def test_real_verify_wrong_message_fails(self):
        """Verification fails when the message doesn't match."""
        kp = generate_signing_keypair(SignatureAlgorithm.ML_DSA_65)
        sig = sign(b"original", kp)
        assert verify(b"tampered", sig, kp.public_key, kp.algorithm) is False

    def test_real_verify_wrong_key_fails(self):
        """Verification fails with a different public key."""
        kp1 = generate_signing_keypair(SignatureAlgorithm.ML_DSA_65)
        kp2 = generate_signing_keypair(SignatureAlgorithm.ML_DSA_65)
        sig = sign(b"test", kp1)
        assert verify(b"test", sig, kp2.public_key, kp1.algorithm) is False

    def test_real_all_signing_algorithms(self):
        """Sign + verify works for every ML-DSA variant."""
        for algo in SignatureAlgorithm:
            kp = generate_signing_keypair(algo)
            msg = f"test-{algo.value}".encode()
            sig = sign(msg, kp)
            assert verify(msg, sig, kp.public_key, algo) is True
