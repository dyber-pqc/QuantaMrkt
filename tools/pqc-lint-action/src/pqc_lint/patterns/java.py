"""Java crypto patterns."""

from __future__ import annotations

from pqc_lint.patterns.base import PatternMatcher, compile_patterns


class JavaMatcher(PatternMatcher):
    language = "java"
    file_extensions = (".java", ".kt")
    patterns = compile_patterns([
        # KeyPairGenerator / KeyFactory
        ("PQC001", r"""KeyPairGenerator\.getInstance\s*\(\s*"RSA"\s*\)"""),
        ("PQC001", r"""Signature\.getInstance\s*\(\s*"SHA\d+withRSA"""),
        ("PQC002", r"""KeyPairGenerator\.getInstance\s*\(\s*"EC"\s*\)"""),
        ("PQC002", r"""Signature\.getInstance\s*\(\s*"SHA\d+withECDSA"""),
        ("PQC003", r"""KeyPairGenerator\.getInstance\s*\(\s*"Ed25519"\s*\)"""),
        ("PQC004", r"""KeyPairGenerator\.getInstance\s*\(\s*"DSA"\s*\)"""),
        ("PQC004", r"""Signature\.getInstance\s*\(\s*"SHA\d+withDSA"""),
        # KeyAgreement
        ("PQC101", r"""KeyAgreement\.getInstance\s*\(\s*"ECDH"\s*\)"""),
        ("PQC102", r"""KeyAgreement\.getInstance\s*\(\s*"DH"\s*\)"""),
        ("PQC102", r"""KeyAgreement\.getInstance\s*\(\s*"DiffieHellman"\s*\)"""),
        ("PQC103", r"""KeyAgreement\.getInstance\s*\(\s*"XDH"\s*\)"""),
        # Cipher
        ("PQC201", r"""Cipher\.getInstance\s*\(\s*"RSA/.*/OAEPWith"""),
        ("PQC202", r"""Cipher\.getInstance\s*\(\s*"RSA/.*/PKCS1Padding"""),
        # hashes
        ("PQC301", r"""MessageDigest\.getInstance\s*\(\s*"MD5"\s*\)"""),
        ("PQC302", r"""MessageDigest\.getInstance\s*\(\s*"SHA-?1"\s*\)"""),
    ])
