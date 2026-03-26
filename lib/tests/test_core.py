"""Tests for core cryptographic primitives."""

import warnings

import pytest

from quantumshield.core.algorithms import KEMAlgorithm, SignatureAlgorithm
from quantumshield.core.keys import (
    KEMKeypair,
    SigningKeypair,
    _BACKEND,
    _HAS_PQC,
    _STUB_KEM_SIZES,
    _STUB_SIG_SIZES,
    generate_kem_keypair,
    generate_signing_keypair,
    get_backend,
    has_pqc,
    has_real_crypto,
)
from quantumshield.core.signatures import sign, verify


# ---------------------------------------------------------------------------
# Key generation (works in all modes)
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


def test_has_real_crypto_returns_bool():
    """has_real_crypto() returns a boolean."""
    assert isinstance(has_real_crypto(), bool)


def test_get_backend_returns_known_value():
    """get_backend() returns one of the known backend names."""
    assert get_backend() in ("liboqs", "ed25519", "stub")


# ---------------------------------------------------------------------------
# Stub-mode specific tests (only run when NEITHER liboqs NOR cryptography)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    _BACKEND != "stub",
    reason="Stub tests only applicable when neither liboqs nor cryptography is installed",
)
class TestStubMode:
    """Tests that verify correct stub behaviour when no real crypto is available."""

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
# Ed25519 transitional tests (only run when cryptography IS installed but
# liboqs is NOT)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    _BACKEND != "ed25519",
    reason="Ed25519 tests only applicable when cryptography is installed without liboqs",
)
class TestEd25519Transitional:
    """Tests that exercise the Ed25519 transitional crypto backend."""

    def test_ed25519_keypair_sizes(self):
        """Ed25519 produces 32-byte public and private keys."""
        kp = generate_signing_keypair()
        assert len(kp.public_key) == 32
        assert len(kp.private_key) == 32

    def test_ed25519_sign_and_verify(self):
        """An Ed25519 signature round-trips through sign + verify."""
        kp = generate_signing_keypair(SignatureAlgorithm.ML_DSA_65)
        message = b"hello transitional crypto"
        sig = sign(message, kp)
        assert isinstance(sig, bytes)
        assert len(sig) == 64  # Ed25519 signatures are 64 bytes
        assert verify(message, sig, kp.public_key, kp.algorithm) is True

    def test_ed25519_verify_wrong_message_fails(self):
        """Ed25519 verification fails when the message doesn't match."""
        kp = generate_signing_keypair(SignatureAlgorithm.ML_DSA_65)
        sig = sign(b"original", kp)
        assert verify(b"tampered", sig, kp.public_key, kp.algorithm) is False

    def test_ed25519_verify_wrong_key_fails(self):
        """Ed25519 verification fails with a different public key."""
        kp1 = generate_signing_keypair(SignatureAlgorithm.ML_DSA_65)
        kp2 = generate_signing_keypair(SignatureAlgorithm.ML_DSA_65)
        sig = sign(b"test", kp1)
        assert verify(b"test", sig, kp2.public_key, kp1.algorithm) is False

    def test_ed25519_all_signing_algorithms_produce_valid_sigs(self):
        """Sign + verify works for all algorithm enum values (all use Ed25519 under the hood)."""
        for algo in SignatureAlgorithm:
            kp = generate_signing_keypair(algo)
            msg = f"test-{algo.value}".encode()
            sig = sign(msg, kp)
            assert verify(msg, sig, kp.public_key, algo) is True

    def test_has_real_crypto_true(self):
        """has_real_crypto() returns True when Ed25519 is available."""
        assert has_real_crypto() is True

    def test_has_pqc_false(self):
        """has_pqc() returns False when only Ed25519 is available."""
        assert has_pqc() is False


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
