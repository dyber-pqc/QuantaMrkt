"""Map classical cryptographic primitives to PQC replacements."""

from __future__ import annotations

# Canonical classical -> PQC replacement map
CLASSICAL_TO_PQC: dict[str, dict[str, str]] = {
    # Signatures
    "RSA-PSS":       {"replacement": "ML-DSA-65 (FIPS 204)", "reason": "RSA is broken by Shor's algorithm. ML-DSA is the NIST PQC signature standard."},
    "RSA-PKCS1v15":  {"replacement": "ML-DSA-65 (FIPS 204)", "reason": "RSA is broken by Shor's algorithm. PKCS1v15 is additionally vulnerable to padding oracle attacks."},
    "RSA-signing":   {"replacement": "ML-DSA-65 (FIPS 204)", "reason": "RSA signatures are broken by Shor's algorithm. Use ML-DSA for quantum-safe signing."},
    "ECDSA":         {"replacement": "ML-DSA-65 (FIPS 204)", "reason": "Elliptic curve signatures are broken by Shor's algorithm. ML-DSA is quantum-safe."},
    "DSA":           {"replacement": "ML-DSA-44 (FIPS 204) or SLH-DSA", "reason": "DSA is broken by Shor's. Deprecated even in classical settings."},
    "Ed25519":       {"replacement": "ML-DSA-44 (FIPS 204)", "reason": "Ed25519 is classical EC signing - broken by Shor's. Consider ML-DSA for PQC; SLH-DSA for stateless hash-based alternative."},

    # Key exchange / encapsulation
    "RSA-encryption":{"replacement": "ML-KEM-768 (FIPS 203)", "reason": "RSA encryption is broken by Shor's. ML-KEM is the NIST PQC KEM standard."},
    "RSA-OAEP":      {"replacement": "ML-KEM-768 (FIPS 203)", "reason": "RSA-OAEP is broken by Shor's algorithm once CRQC exists."},
    "DH":            {"replacement": "ML-KEM-768 (FIPS 203)", "reason": "Finite-field Diffie-Hellman is broken by Shor's algorithm."},
    "ECDH":          {"replacement": "ML-KEM-768 (FIPS 203)", "reason": "Elliptic curve Diffie-Hellman is broken by Shor's algorithm."},
    "X25519":        {"replacement": "ML-KEM-512 (FIPS 203)", "reason": "X25519 is classical EC key agreement - broken by Shor's."},

    # Weak hashes (classical, not strictly quantum but still bad)
    "MD5":           {"replacement": "SHA3-256 or SHAKE-256", "reason": "MD5 is cryptographically broken. Grover's algorithm doesn't make it worse but it's already unusable."},
    "SHA1":          {"replacement": "SHA3-256 or SHAKE-256", "reason": "SHA-1 is broken (SHAttered). Use SHA3-256 for quantum-safe hashing (256-bit -> 128-bit under Grover's)."},
}


def suggest_replacement(classical_name: str) -> str:
    """Return a human-readable suggestion string for a classical primitive."""
    name = classical_name.upper().replace("_", "-").replace(" ", "-")
    # normalize common variants
    lookup_key = None
    for key in CLASSICAL_TO_PQC:
        if key.upper().replace("_", "-") == name:
            lookup_key = key
            break
    if not lookup_key:
        for key in CLASSICAL_TO_PQC:
            if key.upper().split("-")[0] == name.split("-")[0]:
                lookup_key = key
                break
    if not lookup_key:
        return ""
    entry = CLASSICAL_TO_PQC[lookup_key]
    return f"Use {entry['replacement']}. {entry['reason']}"
