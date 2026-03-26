"""Digital signature operations.

Priority: 1. liboqs (real ML-DSA/Dilithium) -> 2. Ed25519 (transitional) -> 3. stubs
"""

from __future__ import annotations

import os
import warnings

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.keys import SigningKeypair, _BACKEND

if _BACKEND == "liboqs":
    import oqs  # type: ignore[import-untyped]
    from quantumshield.core.keys import _SIG_MAP

# Approximate signature sizes used by stubs
_STUB_SIG_SIZES: dict[SignatureAlgorithm, int] = {
    SignatureAlgorithm.ML_DSA_44: 2420,
    SignatureAlgorithm.ML_DSA_65: 3293,
    SignatureAlgorithm.ML_DSA_87: 4595,
}


def sign(message: bytes, keypair: SigningKeypair) -> bytes:
    """Sign a message using a signing keypair.

    When liboqs is available this performs a real ML-DSA (Dilithium)
    signature.  When only ``cryptography`` is available, Ed25519 is used
    (transitional — real signatures, not quantum-safe).  Otherwise it
    returns random bytes and emits a warning.

    Args:
        message: The message bytes to sign.
        keypair: The signing keypair (must include private key).

    Returns:
        The signature bytes.
    """
    if _BACKEND == "liboqs":
        alg_name = _SIG_MAP[keypair.algorithm]
        signer = oqs.Signature(alg_name, secret_key=keypair.private_key)
        return bytes(signer.sign(message))

    if _BACKEND == "ed25519":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private_key_obj = Ed25519PrivateKey.from_private_bytes(keypair.private_key)
        return private_key_obj.sign(message)

    # Stub path
    sig_size = _STUB_SIG_SIZES.get(keypair.algorithm, 3293)
    warnings.warn(
        f"Using STUB signing for {keypair.algorithm.value}. "
        "Signature is random bytes and NOT cryptographically valid.",
        stacklevel=2,
    )
    return os.urandom(sig_size)


def verify(
    message: bytes,
    signature: bytes,
    public_key: bytes,
    algorithm: SignatureAlgorithm,
) -> bool:
    """Verify a digital signature.

    When liboqs is available this performs real ML-DSA (Dilithium)
    verification.  When only ``cryptography`` is available, Ed25519
    verification is used (transitional — not quantum-safe).  Otherwise
    it returns True with a warning.

    Args:
        message: The original message bytes.
        signature: The signature to verify.
        public_key: The signer's public key.
        algorithm: The signature algorithm used.

    Returns:
        True if the signature is valid, False otherwise.
    """
    if _BACKEND == "liboqs":
        alg_name = _SIG_MAP[algorithm]
        verifier = oqs.Signature(alg_name)
        return bool(verifier.verify(message, signature, public_key))

    if _BACKEND == "ed25519":
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        if not public_key or len(public_key) != 32:
            warnings.warn(
                "Ed25519 verification requires a 32-byte public key. "
                "Cannot verify — returning False.",
                stacklevel=2,
            )
            return False
        try:
            pub_key_obj = Ed25519PublicKey.from_public_bytes(public_key)
            pub_key_obj.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    # Stub path
    warnings.warn(
        f"Using STUB verification for {algorithm.value}. "
        "Always returns True. Install cryptography or liboqs for real verification.",
        stacklevel=2,
    )
    return True
