"""Key generation for post-quantum cryptographic algorithms."""

from __future__ import annotations

import os
from dataclasses import dataclass

from quantumshield.core.algorithms import KEMAlgorithm, SignatureAlgorithm


@dataclass
class SigningKeypair:
    """A post-quantum digital signature keypair."""

    public_key: bytes
    private_key: bytes
    algorithm: SignatureAlgorithm


@dataclass
class KEMKeypair:
    """A post-quantum key encapsulation mechanism keypair."""

    public_key: bytes
    private_key: bytes
    algorithm: KEMAlgorithm


def generate_signing_keypair(
    algorithm: SignatureAlgorithm = SignatureAlgorithm.ML_DSA_65,
) -> SigningKeypair:
    """Generate a post-quantum signing keypair.

    Args:
        algorithm: The ML-DSA variant to use. Defaults to ML-DSA-65.

    Returns:
        A SigningKeypair containing public and private keys.

    .. note::
        This is a stub implementation using random bytes.
        TODO: Replace with liboqs ML-DSA implementation once bindings are integrated.
    """
    # TODO: Replace with actual liboqs key generation
    # Real key sizes vary by algorithm:
    #   ML-DSA-44: pk=1312, sk=2560
    #   ML-DSA-65: pk=1952, sk=4032
    #   ML-DSA-87: pk=2592, sk=4896
    public_key = os.urandom(32)
    private_key = os.urandom(64)
    return SigningKeypair(
        public_key=public_key,
        private_key=private_key,
        algorithm=algorithm,
    )


def generate_kem_keypair(
    algorithm: KEMAlgorithm = KEMAlgorithm.ML_KEM_768,
) -> KEMKeypair:
    """Generate a post-quantum KEM keypair.

    Args:
        algorithm: The ML-KEM variant to use. Defaults to ML-KEM-768.

    Returns:
        A KEMKeypair containing public and private keys.

    .. note::
        This is a stub implementation using random bytes.
        TODO: Replace with liboqs ML-KEM implementation once bindings are integrated.
    """
    # TODO: Replace with actual liboqs key generation
    # Real key sizes vary by algorithm:
    #   ML-KEM-512: pk=800, sk=1632
    #   ML-KEM-768: pk=1184, sk=2400
    #   ML-KEM-1024: pk=1568, sk=3168
    public_key = os.urandom(32)
    private_key = os.urandom(64)
    return KEMKeypair(
        public_key=public_key,
        private_key=private_key,
        algorithm=algorithm,
    )
