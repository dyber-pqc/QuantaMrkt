"""Rust crypto patterns."""

from __future__ import annotations

from pqc_lint.patterns.base import PatternMatcher, compile_patterns


class RustMatcher(PatternMatcher):
    language = "rust"
    file_extensions = (".rs",)
    patterns = compile_patterns([
        ("PQC001", r"\buse\s+rsa\b"),
        ("PQC001", r"\brsa::RsaPrivateKey::new\s*\("),
        ("PQC002", r"\buse\s+ecdsa\b"),
        ("PQC002", r"\buse\s+p256\b"),
        ("PQC002", r"\buse\s+p384\b"),
        ("PQC002", r"\buse\s+k256\b"),
        ("PQC003", r"\buse\s+ed25519_dalek\b"),
        ("PQC003", r"\bed25519_dalek::Keypair::generate\s*\("),
        ("PQC103", r"\buse\s+x25519_dalek\b"),
        ("PQC103", r"\bx25519_dalek::EphemeralSecret\b"),
        # ring
        ("PQC001", r"\bring::rsa\b"),
        ("PQC002", r"\bring::signature::ECDSA"),
        ("PQC101", r"\bring::agreement::ECDH"),
        # hashes
        ("PQC301", r"\buse\s+md5\b"),
        ("PQC301", r"\bmd5::Md5\b"),
        ("PQC302", r"\buse\s+sha1\b"),
        ("PQC302", r"\bsha1::Sha1\b"),
    ])
