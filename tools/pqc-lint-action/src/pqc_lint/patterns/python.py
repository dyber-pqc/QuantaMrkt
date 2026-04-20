"""Python-specific crypto patterns."""

from __future__ import annotations

from pqc_lint.patterns.base import PatternMatcher, compile_patterns


class PythonMatcher(PatternMatcher):
    language = "python"
    file_extensions = (".py",)
    patterns = compile_patterns([
        # cryptography library
        ("PQC001", r"\brsa\.generate_private_key\s*\("),
        ("PQC001", r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+rsa\b"),
        ("PQC001", r"\bpadding\.PSS\s*\("),
        ("PQC001", r"\bpadding\.PKCS1v15\s*\("),
        ("PQC002", r"\bec\.generate_private_key\s*\("),
        ("PQC002", r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+ec\b"),
        ("PQC002", r"\bec\.ECDSA\s*\("),
        ("PQC003", r"\bed25519\.Ed25519PrivateKey\b"),
        ("PQC003", r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+ed25519\b"),
        ("PQC004", r"\bdsa\.generate_private_key\s*\("),
        ("PQC004", r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+dsa\b"),
        ("PQC101", r"\bec\.ECDH\s*\("),
        ("PQC102", r"\bdh\.generate_parameters\s*\("),
        ("PQC102", r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+dh\b"),
        ("PQC103", r"\bx25519\.X25519PrivateKey\b"),
        ("PQC201", r"\bpadding\.OAEP\s*\("),
        ("PQC202", r"\bPKCS1_v1_5\b"),
        # pycryptodome
        ("PQC001", r"\bfrom\s+Crypto\.PublicKey\s+import\s+RSA\b"),
        ("PQC001", r"\bRSA\.generate\s*\("),
        ("PQC002", r"\bfrom\s+Crypto\.PublicKey\s+import\s+ECC\b"),
        ("PQC002", r"\bECC\.generate\s*\("),
        # ecdsa library
        ("PQC002", r"\bimport\s+ecdsa\b"),
        ("PQC002", r"\bfrom\s+ecdsa\s+import\b"),
        # hashes
        ("PQC301", r"\bhashlib\.md5\s*\("),
        ("PQC301", r"\bhashes\.MD5\s*\("),
        ("PQC302", r"\bhashlib\.sha1\s*\("),
        ("PQC302", r"\bhashes\.SHA1\s*\("),
    ])
