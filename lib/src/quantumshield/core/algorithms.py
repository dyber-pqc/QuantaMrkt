"""Post-quantum cryptographic algorithm enumerations."""

from enum import Enum


class SignatureAlgorithm(str, Enum):
    """NIST-standardized post-quantum signature algorithms (FIPS 204)."""

    ML_DSA_44 = "ML-DSA-44"
    ML_DSA_65 = "ML-DSA-65"
    ML_DSA_87 = "ML-DSA-87"


class KEMAlgorithm(str, Enum):
    """NIST-standardized post-quantum key encapsulation mechanisms (FIPS 203)."""

    ML_KEM_512 = "ML-KEM-512"
    ML_KEM_768 = "ML-KEM-768"
    ML_KEM_1024 = "ML-KEM-1024"


class HashAlgorithm(str, Enum):
    """Quantum-resistant hash algorithms."""

    SHA3_256 = "SHA3-256"
    SHA3_512 = "SHA3-512"
