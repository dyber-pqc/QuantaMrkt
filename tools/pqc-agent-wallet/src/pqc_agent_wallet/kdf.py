"""Key derivation - derive a 32-byte symmetric key from a passphrase."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DEFAULT_ITERATIONS = 600_000  # OWASP 2023 recommendation for PBKDF2-SHA256


def derive_key_from_passphrase(
    passphrase: str,
    salt: bytes,
    iterations: int = DEFAULT_ITERATIONS,
    length: int = 32,
) -> bytes:
    """Derive a symmetric key from a passphrase using PBKDF2-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))
