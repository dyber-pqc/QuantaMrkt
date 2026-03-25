"""Tests for the migration analyzer and pattern matching."""

import re

from quantumshield.migrator.analyzer import MigrationAgent, MigrationReport
from quantumshield.migrator.patterns import VULNERABILITY_PATTERNS


def test_patterns_dict_has_required_entries():
    """Test that the patterns dict contains all 15 required patterns."""
    expected = {
        "RSA_KEYGEN", "ECDH_EXCHANGE", "ECDSA_SIGN", "RSA_ENCRYPT",
        "DH_EXCHANGE", "DSA_SIGN", "MD5_HASH", "SHA1_HASH",
        "AES_CBC", "STATIC_IV", "HARDCODED_KEY", "WEAK_RANDOM",
        "RSA_PKCS1V15", "TRIPLE_DES", "RC4",
    }
    assert expected.issubset(set(VULNERABILITY_PATTERNS.keys()))


def test_rsa_keygen_pattern():
    """Test RSA key generation pattern matches known code."""
    pattern = re.compile(VULNERABILITY_PATTERNS["RSA_KEYGEN"]["pattern"], re.IGNORECASE)
    assert pattern.search("key = RSA.generate(2048)")
    assert pattern.search("from Crypto.PublicKey import RSA; k = RSA.generate(4096)")
    assert not pattern.search("aes_key = AES.new(key)")


def test_ecdsa_pattern():
    """Test ECDSA pattern matches elliptic curve signing code."""
    pattern = re.compile(VULNERABILITY_PATTERNS["ECDSA_SIGN"]["pattern"], re.IGNORECASE)
    assert pattern.search("private_key = ec.generate_private_key(SECP256R1())")
    assert pattern.search("signer = ECDSA(key)")
    assert not pattern.search("sha256_hash = hashlib.sha256(data)")


def test_md5_pattern():
    """Test MD5 hash pattern detection."""
    pattern = re.compile(VULNERABILITY_PATTERNS["MD5_HASH"]["pattern"], re.IGNORECASE)
    assert pattern.search("digest = hashlib.md5(data)")
    assert pattern.search('MessageDigest.getInstance("MD5")')
    assert not pattern.search("hashlib.sha3_256(data)")


def test_weak_random_pattern():
    """Test weak random number generator detection."""
    pattern = re.compile(VULNERABILITY_PATTERNS["WEAK_RANDOM"]["pattern"], re.IGNORECASE)
    assert pattern.search("key = random.random()")
    assert pattern.search("var x = Math.random()")
    assert not pattern.search("secrets.token_bytes(32)")


def test_hardcoded_key_pattern():
    """Test hardcoded key detection."""
    pattern = re.compile(VULNERABILITY_PATTERNS["HARDCODED_KEY"]["pattern"], re.IGNORECASE)
    assert pattern.search('secret_key = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q="')
    assert pattern.search('encryption_key = "0123456789abcdef0123456789abcdef"')


def test_rc4_pattern():
    """Test RC4 cipher detection."""
    pattern = re.compile(VULNERABILITY_PATTERNS["RC4"]["pattern"], re.IGNORECASE)
    assert pattern.search("cipher = ARC4.new(key)")
    assert pattern.search('Cipher.getInstance("RC4")')
    assert not pattern.search("cipher = AES.new(key, AES.MODE_GCM)")


def test_analyzer_on_sample_code(tmp_path):
    """Test the MigrationAgent on a sample Python file with known vulnerabilities."""
    sample = tmp_path / "crypto_sample.py"
    sample.write_text(
        'import hashlib\n'
        'from Crypto.PublicKey import RSA\n'
        '\n'
        'key = RSA.generate(2048)\n'
        'digest = hashlib.md5(b"hello")\n'
        'iv = b"1234567890abcdef"\n'
        'secret_key = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q="\n'
    )

    agent = MigrationAgent()
    report = agent.analyze(str(tmp_path))

    assert isinstance(report, MigrationReport)
    assert report.files_scanned == 1
    assert report.files_with_crypto == 1
    assert len(report.vulnerabilities) >= 3

    pattern_names = {v.pattern_name for v in report.vulnerabilities}
    assert "RSA_KEYGEN" in pattern_names
    assert "MD5_HASH" in pattern_names


def test_analyzer_empty_directory(tmp_path):
    """Test analyzer on a directory with no source files."""
    agent = MigrationAgent()
    report = agent.analyze(str(tmp_path))
    assert report.files_scanned == 0
    assert len(report.vulnerabilities) == 0
    assert report.effort_estimate == "none"
