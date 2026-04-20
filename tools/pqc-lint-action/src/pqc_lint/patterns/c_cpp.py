"""C / C++ crypto patterns (mostly OpenSSL)."""

from __future__ import annotations

from pqc_lint.patterns.base import PatternMatcher, compile_patterns


class CCppMatcher(PatternMatcher):
    language = "c"
    file_extensions = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")
    patterns = compile_patterns([
        # OpenSSL legacy API
        ("PQC001", r"\bRSA_generate_key\s*\("),
        ("PQC001", r"\bRSA_sign\s*\("),
        ("PQC201", r"\bRSA_public_encrypt\s*\("),
        ("PQC202", r"\bRSA_private_decrypt\s*\("),
        ("PQC002", r"\bEC_KEY_generate_key\s*\("),
        ("PQC002", r"\bECDSA_sign\s*\("),
        ("PQC101", r"\bECDH_compute_key\s*\("),
        ("PQC102", r"\bDH_generate_key\s*\("),
        ("PQC102", r"\bDH_compute_key\s*\("),
        # OpenSSL EVP API
        ("PQC001", r"""EVP_PKEY_RSA\b"""),
        ("PQC002", r"""EVP_PKEY_EC\b"""),
        ("PQC004", r"""EVP_PKEY_DSA\b"""),
        ("PQC102", r"""EVP_PKEY_DH\b"""),
        # hashes
        ("PQC301", r"\bMD5_Init\s*\("),
        ("PQC301", r"\bEVP_md5\s*\("),
        ("PQC302", r"\bSHA1_Init\s*\("),
        ("PQC302", r"\bEVP_sha1\s*\("),
    ])
