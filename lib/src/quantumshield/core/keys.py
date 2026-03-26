"""Key generation for post-quantum cryptographic algorithms."""

from __future__ import annotations

import os
import warnings
from dataclasses import dataclass

from quantumshield.core.algorithms import KEMAlgorithm, SignatureAlgorithm

# ---------------------------------------------------------------------------
# PQC backend detection
# ---------------------------------------------------------------------------
# Try liboqs (best performance, real NIST PQC). Fall back to stubs with a
# clear warning so the library remains usable without native dependencies.
# ---------------------------------------------------------------------------

try:
    import oqs  # type: ignore[import-untyped]

    _HAS_PQC = True

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
    _HAS_PQC = False
    # Only warn once, and only when not running as CLI (avoids noise on every command)
    warnings.warn(
        "liboqs not installed — using stub crypto (random bytes). "
        "Install liboqs-python for real PQC:  pip install quantumshield[pqc]",
        stacklevel=1,
    )
    # Suppress future duplicate warnings from this module
    warnings.filterwarnings("ignore", message="liboqs not installed")

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
    return _HAS_PQC


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

    When liboqs is available the keypair is generated using real ML-DSA
    (Dilithium).  Otherwise random bytes of the correct approximate size
    are returned together with a runtime warning.

    Args:
        algorithm: The ML-DSA variant to use. Defaults to ML-DSA-65.

    Returns:
        A SigningKeypair containing public and private keys.
    """
    if _HAS_PQC:
        alg_name = _SIG_MAP[algorithm]
        signer = oqs.Signature(alg_name)  # type: ignore[union-attr]
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()
        return SigningKeypair(
            public_key=bytes(public_key),
            private_key=bytes(private_key),
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
    if _HAS_PQC:
        alg_name = _KEM_MAP[algorithm]
        kem = oqs.KeyEncapsulation(alg_name)  # type: ignore[union-attr]
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
        return KEMKeypair(
            public_key=bytes(public_key),
            private_key=bytes(private_key),
            algorithm=algorithm,
        )

    # Stub path
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
