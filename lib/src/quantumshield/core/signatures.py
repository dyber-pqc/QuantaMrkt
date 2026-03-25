"""Post-quantum digital signature operations."""

from __future__ import annotations

import os

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.keys import SigningKeypair


def sign(message: bytes, keypair: SigningKeypair) -> bytes:
    """Sign a message using a post-quantum signing keypair.

    Args:
        message: The message bytes to sign.
        keypair: The signing keypair (must include private key).

    Returns:
        The signature bytes.

    .. note::
        Stub implementation. TODO: Replace with liboqs ML-DSA sign operation.
    """
    # TODO: Replace with actual liboqs ML-DSA signing
    # For now, return random bytes as a placeholder signature
    return os.urandom(64)


def verify(
    message: bytes,
    signature: bytes,
    public_key: bytes,
    algorithm: SignatureAlgorithm,
) -> bool:
    """Verify a post-quantum digital signature.

    Args:
        message: The original message bytes.
        signature: The signature to verify.
        public_key: The signer's public key.
        algorithm: The signature algorithm used.

    Returns:
        True if the signature is valid, False otherwise.

    .. note::
        Stub implementation. TODO: Replace with liboqs ML-DSA verify operation.
    """
    # TODO: Replace with actual liboqs ML-DSA verification
    # For now, always return True as a placeholder
    return True
