"""Go crypto patterns."""

from __future__ import annotations

from pqc_lint.patterns.base import PatternMatcher, compile_patterns


class GoMatcher(PatternMatcher):
    language = "go"
    file_extensions = (".go",)
    patterns = compile_patterns([
        # imports
        ("PQC001", r"""["`]crypto/rsa["`]"""),
        ("PQC002", r"""["`]crypto/ecdsa["`]"""),
        ("PQC003", r"""["`]crypto/ed25519["`]"""),
        ("PQC004", r"""["`]crypto/dsa["`]"""),
        # function calls
        ("PQC001", r"\brsa\.GenerateKey\s*\("),
        ("PQC001", r"\brsa\.SignPKCS1v15\s*\("),
        ("PQC001", r"\brsa\.SignPSS\s*\("),
        ("PQC201", r"\brsa\.EncryptOAEP\s*\("),
        ("PQC202", r"\brsa\.EncryptPKCS1v15\s*\("),
        ("PQC002", r"\becdsa\.GenerateKey\s*\("),
        ("PQC002", r"\becdsa\.Sign(?:ASN1)?\s*\("),
        ("PQC003", r"\bed25519\.GenerateKey\s*\("),
        ("PQC003", r"\bed25519\.Sign\s*\("),
        # hashes
        ("PQC301", r"""["`]crypto/md5["`]"""),
        ("PQC301", r"\bmd5\.New\s*\("),
        ("PQC301", r"\bmd5\.Sum\s*\("),
        ("PQC302", r"""["`]crypto/sha1["`]"""),
        ("PQC302", r"\bsha1\.New\s*\("),
        ("PQC302", r"\bsha1\.Sum\s*\("),
    ])
