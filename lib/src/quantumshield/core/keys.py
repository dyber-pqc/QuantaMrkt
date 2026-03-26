"""Key generation for post-quantum cryptographic algorithms.

Priority: 1. liboqs (real PQC) -> 2. cryptography (Ed25519, transitional) -> 3. stubs
"""

from __future__ import annotations

import os
import warnings
from dataclasses import dataclass

from quantumshield.core.algorithms import KEMAlgorithm, SignatureAlgorithm

# ---------------------------------------------------------------------------
# PQC backend detection
# ---------------------------------------------------------------------------
# Try liboqs first (best: real NIST PQC).
# Then try cryptography for Ed25519 (transitional: real crypto, not PQC).
# Fall back to stubs with a clear warning.
# ---------------------------------------------------------------------------

_BACKEND: str = "stub"  # "liboqs" | "ed25519" | "stub"

try:
    import oqs  # type: ignore[import-untyped]

    _BACKEND = "liboqs"

    # Map our enums to liboqs algorithm names
    _SIG_MAP: dict[SignatureAlgorithm, str] = {
        SignatureAlgorithm.ML_DSA_44: "Dilithium2",
        SignatureAlgorithm.ML_DSA_65: "Dilithium3",
        SignatureAlgorithm.ML_DSA_87: "Dilithium5",
    }

    _KEM_MAP: dict[KEMAlgorithm, str] = {
        KEMAlgorithm.ML_KEM_512: "Kyber512",
        KEMAlgorithm.ML_KEM_768: "Kyber768",
        KEMAlgorithm.ML_KEM_1024: "Kyber1024",
    }
except ImportError:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey as _Ed25519PrivateKey,
        )

        _BACKEND = "ed25519"
        warnings.warn(
            "liboqs not installed — using Ed25519 (transitional, NOT quantum-safe). "
            "Signatures are cryptographically valid but not post-quantum. "
            "Install liboqs-python for real PQC:  pip install quantumshield[pqc]",
            stacklevel=1,
        )
    except ImportError:
        warnings.warn(
            "Neither liboqs nor cryptography installed — using stub crypto (random bytes). "
            "Install cryptography for real signatures:  pip install cryptography\n"
            "Install liboqs-python for real PQC:  pip install quantumshield[pqc]",
            stacklevel=1,
        )
    # Suppress future duplicate warnings from this module
    warnings.filterwarnings("ignore", message="liboqs not installed")
    warnings.filterwarnings("ignore", message="Neither liboqs nor cryptography")

# Legacy alias kept for existing imports
_HAS_PQC = _BACKEND == "liboqs"

# Approximate real key sizes used by stubs so downstream code behaves
# consistently regardless of backend.
_STUB_SIG_SIZES: dict[SignatureAlgorithm, tuple[int, int]] = {
    SignatureAlgorithm.ML_DSA_44: (1312, 2560),
    SignatureAlgorithm.ML_DSA_65: (1952, 4032),
    SignatureAlgorithm.ML_DSA_87: (2592, 4896),
}

_STUB_KEM_SIZES: dict[KEMAlgorithm, tuple[int, int]] = {
    KEMAlgorithm.ML_KEM_512: (800, 1632),
    KEMAlgorithm.ML_KEM_768: (1184, 2400),
    KEMAlgorithm.ML_KEM_1024: (1568, 3168),
}


def has_pqc() -> bool:
    """Return True if a real PQC backend (liboqs) is available."""
    return _BACKEND == "liboqs"


def has_real_crypto() -> bool:
    """Return True if any real cryptographic backend is available (liboqs or Ed25519)."""
    return _BACKEND in ("liboqs", "ed25519")


def get_backend() -> str:
    """Return the name of the active crypto backend: 'liboqs', 'ed25519', or 'stub'."""
    return _BACKEND


@dataclass
class SigningKeypair:
    """A digital signature keypair.

    When using liboqs, this holds ML-DSA keys.
    When using Ed25519 transitional mode, public_key is 32 bytes and
    private_key is the 32-byte Ed25519 seed.
    """

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
    """Generate a signing keypair.

    When liboqs is available the keypair is generated using real ML-DSA
    (Dilithium).  When only ``cryptography`` is available, Ed25519 keys
    are generated (transitional — real crypto, not quantum-safe).
    Otherwise random bytes of the correct approximate size are returned.

    Args:
        algorithm: The ML-DSA variant to use. Defaults to ML-DSA-65.
                   Ignored when falling back to Ed25519.

    Returns:
        A SigningKeypair containing public and private keys.
    """
    if _BACKEND == "liboqs":
        alg_name = _SIG_MAP[algorithm]
        signer = oqs.Signature(alg_name)  # type: ignore[union-attr]
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()
        return SigningKeypair(
            public_key=bytes(public_key),
            private_key=bytes(private_key),
            algorithm=algorithm,
        )

    if _BACKEND == "ed25519":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )

        private_key_obj = Ed25519PrivateKey.generate()
        public_bytes = private_key_obj.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        private_bytes = private_key_obj.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
        return SigningKeypair(
            public_key=public_bytes,
            private_key=private_bytes,
            algorithm=algorithm,
        )

    # Stub path — random bytes with correct approximate sizes
    pk_size, sk_size = _STUB_SIG_SIZES[algorithm]
    warnings.warn(
        f"Generating STUB signing keypair for {algorithm.value}. "
        "Keys are random bytes and NOT cryptographically valid.",
        stacklevel=2,
    )
    return SigningKeypair(
        public_key=os.urandom(pk_size),
        private_key=os.urandom(sk_size),
        algorithm=algorithm,
    )


def generate_kem_keypair(
    algorithm: KEMAlgorithm = KEMAlgorithm.ML_KEM_768,
) -> KEMKeypair:
    """Generate a post-quantum KEM keypair.

    When liboqs is available the keypair is generated using real ML-KEM
    (Kyber).  Otherwise random bytes of the correct approximate size
    are returned together with a runtime warning.

    Args:
        algorithm: The ML-KEM variant to use. Defaults to ML-KEM-768.

    Returns:
        A KEMKeypair containing public and private keys.
    """
    if _BACKEND == "liboqs":
        alg_name = _KEM_MAP[algorithm]
        kem = oqs.KeyEncapsulation(alg_name)  # type: ignore[union-attr]
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
        return KEMKeypair(
            public_key=bytes(public_key),
            private_key=bytes(private_key),
            algorithm=algorithm,
        )

    # Stub path (Ed25519 doesn't provide KEM)
    pk_size, sk_size = _STUB_KEM_SIZES[algorithm]
    warnings.warn(
        f"Generating STUB KEM keypair for {algorithm.value}. "
        "Keys are random bytes and NOT cryptographically valid.",
        stacklevel=2,
    )
    return KEMKeypair(
        public_key=os.urandom(pk_size),
        private_key=os.urandom(sk_size),
        algorithm=algorithm,
    )
