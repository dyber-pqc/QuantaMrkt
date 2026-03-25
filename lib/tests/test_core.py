"""Tests for core cryptographic primitives."""

from quantumshield.core.algorithms import KEMAlgorithm, SignatureAlgorithm
from quantumshield.core.keys import (
    KEMKeypair,
    SigningKeypair,
    generate_kem_keypair,
    generate_signing_keypair,
)


def test_generate_signing_keypair_default():
    """Test that signing keypair generation returns correct types with default algorithm."""
    keypair = generate_signing_keypair()
    assert isinstance(keypair, SigningKeypair)
    assert isinstance(keypair.public_key, bytes)
    assert isinstance(keypair.private_key, bytes)
    assert keypair.algorithm == SignatureAlgorithm.ML_DSA_65
    assert len(keypair.public_key) == 32
    assert len(keypair.private_key) == 64


def test_generate_signing_keypair_all_algorithms():
    """Test signing keypair generation with each algorithm variant."""
    for algo in SignatureAlgorithm:
        keypair = generate_signing_keypair(algo)
        assert keypair.algorithm == algo
        assert len(keypair.public_key) > 0
        assert len(keypair.private_key) > 0


def test_generate_kem_keypair_default():
    """Test that KEM keypair generation returns correct types with default algorithm."""
    keypair = generate_kem_keypair()
    assert isinstance(keypair, KEMKeypair)
    assert isinstance(keypair.public_key, bytes)
    assert isinstance(keypair.private_key, bytes)
    assert keypair.algorithm == KEMAlgorithm.ML_KEM_768
    assert len(keypair.public_key) == 32
    assert len(keypair.private_key) == 64


def test_generate_kem_keypair_all_algorithms():
    """Test KEM keypair generation with each algorithm variant."""
    for algo in KEMAlgorithm:
        keypair = generate_kem_keypair(algo)
        assert keypair.algorithm == algo
        assert len(keypair.public_key) > 0
        assert len(keypair.private_key) > 0


def test_keypairs_are_unique():
    """Test that each keypair generation produces unique keys."""
    kp1 = generate_signing_keypair()
    kp2 = generate_signing_keypair()
    assert kp1.public_key != kp2.public_key
    assert kp1.private_key != kp2.private_key
