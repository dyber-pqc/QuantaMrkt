"""Post-quantum digital signature operations."""

from __future__ import annotations

import os
import warnings

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.keys import SigningKeypair, _HAS_PQC

if _HAS_PQC:
    import oqs  # type: ignore[import-untyped]
    from quantumshield.core.keys import _SIG_MAP

# Approximate signature sizes used by stubs
_STUB_SIG_SIZES: dict[SignatureAlgorithm, int] = {
    SignatureAlgorithm.ML_DSA_44: 2420,
    SignatureAlgorithm.ML_DSA_65: 3293,
    SignatureAlgorithm.ML_DSA_87: 4595,
}


def sign(message: bytes, keypair: SigningKeypair) -> bytes:
    """Sign a message using a post-quantum signing keypair.

    When liboqs is available this performs a real ML-DSA (Dilithium)
    signature.  Otherwise it returns random bytes of the approximate
    correct size and emits a warning.

    Args:
        message: The message bytes to sign.
        keypair: The signing keypair (must include private key).

    Returns:
        The signature bytes.
    """
    if _HAS_PQC:
        alg_name = _SIG_MAP[keypair.algorithm]
        signer = oqs.Signature(alg_name, secret_key=keypair.private_key)
        return bytes(signer.sign(message))

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
    """Verify a post-quantum digital signature.

    When liboqs is available this performs real ML-DSA (Dilithium)
    verification.  Otherwise it returns True with a warning.

    Args:
        message: The original message bytes.
        signature: The signature to verify.
        public_key: The signer's public key.
        algorithm: The signature algorithm used.

    Returns:
        True if the signature is valid, False otherwise.
    """
    if _HAS_PQC:
        alg_name = _SIG_MAP[algorithm]
        verifier = oqs.Signature(alg_name)
        return bool(verifier.verify(message, signature, public_key))

    # Stub path
    warnings.warn(
        f"Using STUB verification for {algorithm.value}. "
        "Always returns True. Install liboqs for real verification.",
        stacklevel=2,
    )
    return True
