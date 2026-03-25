"""Vulnerability patterns for detecting quantum-vulnerable cryptography in source code.

Each pattern includes a regex, risk classification, description, and suggested
post-quantum replacement.
"""

from __future__ import annotations

# Risk levels
CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

VULNERABILITY_PATTERNS: dict[str, dict] = {
    "RSA_KEYGEN": {
        "pattern": r"RSA\.generate\s*\(|rsa_generate_key|generate_private_key\s*\(\s*rsa\b|RSAKeyPair|new\s+RSAKeyGenParameterSpec",
        "risk_level": CRITICAL,
        "description": "RSA key generation detected. RSA is fully broken by Shor's algorithm on a quantum computer.",
        "replacement": "Replace with ML-DSA (FIPS 204) for signatures or ML-KEM (FIPS 203) for key encapsulation.",
        "languages": ["python", "java", "javascript", "go", "rust", "c", "cpp"],
    },
    "ECDH_EXCHANGE": {
        "pattern": r"ECDH\s*\(|ecdh_compute_key|derive_shared_key.*ecdh|X25519|X448|generate_dh_parameters|ECDiffieHellman",
        "risk_level": CRITICAL,
        "description": "Elliptic Curve Diffie-Hellman key exchange detected. ECDH is broken by quantum computers.",
        "replacement": "Replace with ML-KEM (FIPS 203) key encapsulation mechanism.",
        "languages": ["python", "java", "javascript", "go", "rust", "c", "cpp"],
    },
    "ECDSA_SIGN": {
        "pattern": r"ECDSA\s*\(|ec\.generate_private_key|SECP256R1|SECP384R1|SECP521R1|secp256k1|sign.*ecdsa|ECDSAWithSHA",
        "risk_level": CRITICAL,
        "description": "ECDSA signing detected. All elliptic curve signatures are broken by quantum computers.",
        "replacement": "Replace with ML-DSA (FIPS 204) post-quantum digital signatures.",
        "languages": ["python", "java", "javascript", "go", "rust", "c", "cpp"],
    },
    "RSA_ENCRYPT": {
        "pattern": r"RSA/ECB|RSAES-OAEP|rsa_encrypt|RSA\.encrypt|PKCS1_OAEP|RSA_public_encrypt",
        "risk_level": CRITICAL,
        "description": "RSA encryption detected. RSA is fully broken by Shor's algorithm.",
        "replacement": "Replace with ML-KEM (FIPS 203) for key encapsulation, then use AES-256-GCM for data encryption.",
        "languages": ["python", "java", "javascript", "go", "rust", "c", "cpp"],
    },
    "DH_EXCHANGE": {
        "pattern": r"DiffieHellman|DHParameterSpec|generate_dh_parameters|DH_generate_key|dh_compute_key|create_dh|DHE_",
        "risk_level": CRITICAL,
        "description": "Diffie-Hellman key exchange detected. DH is fully broken by Shor's algorithm.",
        "replacement": "Replace with ML-KEM (FIPS 203) key encapsulation mechanism.",
        "languages": ["python", "java", "javascript", "go", "rust", "c", "cpp"],
    },
    "DSA_SIGN": {
        "pattern": r"DSA\.generate|dsa_generate|DSAParameterSpec|generate_private_key\s*\(\s*dsa\b|DSA_sign|SignatureAlgorithm\.DSA",
        "risk_level": CRITICAL,
        "description": "DSA signature algorithm detected. DSA is broken by quantum computers.",
        "replacement": "Replace with ML-DSA (FIPS 204) post-quantum digital signatures.",
        "languages": ["python", "java", "javascript", "go", "rust", "c", "cpp"],
    },
    "MD5_HASH": {
        "pattern": r"MD5\s*\(|md5\s*\(|hashlib\.md5|MessageDigest\.getInstance\s*\(\s*[\"']MD5|MD5_Init|EVP_md5|Md5::",
        "risk_level": HIGH,
        "description": "MD5 hash function detected. MD5 is cryptographically broken (collisions) and has reduced quantum resistance.",
        "replacement": "Replace with SHA3-256 for quantum-resistant hashing.",
        "languages": ["python", "java", "javascript", "go", "rust", "c", "cpp"],
    },
    "SHA1_HASH": {
        "pattern": r"SHA-?1\s*\(|sha1\s*\(|hashlib\.sha1|MessageDigest\.getInstance\s*\(\s*[\"']SHA-?1|SHA1_Init|EVP_sha1",
        "risk_level": HIGH,
        "description": "SHA-1 hash function detected. SHA-1 has known collision attacks and reduced quantum resistance.",
        "replacement": "Replace with SHA3-256 for quantum-resistant hashing.",
        "languages": ["python", "java", "javascript", "go", "rust", "c", "cpp"],
    },
    "AES_CBC": {
        "pattern": r"AES/CBC|AES\.MODE_CBC|aes-128-cbc|aes-256-cbc|CipherMode\.CBC|EVP_aes_\d+_cbc",
        "risk_level": MEDIUM,
        "description": "AES-CBC mode detected. While AES itself is quantum-safe, CBC mode is vulnerable to padding oracle attacks.",
        "replacement": "Replace with AES-256-GCM for authenticated encryption.",
        "languages": ["python", "java", "javascript", "go", "rust", "c", "cpp"],
    },
    "STATIC_IV": {
        "pattern": r"iv\s*=\s*b?[\"'][^\"']+[\"']|IV\s*=\s*b?[\"'][^\"']+[\"']|nonce\s*=\s*b?[\"'][^\"']+[\"']|static.*iv\b|fixed.*iv\b",
        "risk_level": HIGH,
        "description": "Static or hardcoded initialization vector detected. Reusing IVs compromises encryption security.",
        "replacement": "Generate a fresh random IV/nonce for each encryption operation using os.urandom() or equivalent CSPRNG.",
        "languages": ["python", "java", "javascript", "go", "rust", "c", "cpp"],
    },
    "HARDCODED_KEY": {
        "pattern": r"(?:secret_key|encryption_key|private_key|api_key|secret)\s*=\s*b?[\"'][a-zA-Z0-9+/=]{16,}[\"']",
        "risk_level": CRITICAL,
        "description": "Hardcoded cryptographic key detected. Hardcoded keys are trivially extractable.",
        "replacement": "Use a secure key management system (KMS) or derive keys from a key derivation function (HKDF).",
        "languages": ["python", "java", "javascript", "go", "rust", "c", "cpp"],
    },
    "WEAK_RANDOM": {
        "pattern": r"random\.random\s*\(|Math\.random\s*\(|java\.util\.Random\b|rand\s*\(\s*\)|srand\s*\(|mt_rand\s*\(",
        "risk_level": HIGH,
        "description": "Weak random number generator used for potential cryptographic purpose. Non-CSPRNG sources are predictable.",
        "replacement": "Use secrets.token_bytes() (Python), crypto.getRandomValues() (JS), or SecureRandom (Java).",
        "languages": ["python", "java", "javascript", "go", "rust", "c", "cpp"],
    },
    "RSA_PKCS1V15": {
        "pattern": r"PKCS1v15|PKCS1_v1_5|RSA/ECB/PKCS1Padding|RSAES-PKCS1-v1_5|RSA_PKCS1_PADDING",
        "risk_level": CRITICAL,
        "description": "RSA PKCS#1 v1.5 padding detected. Vulnerable to Bleichenbacher attacks and broken by quantum computers.",
        "replacement": "Replace with ML-KEM (FIPS 203) for key transport. If RSA is still needed short-term, use OAEP padding.",
        "languages": ["python", "java", "javascript", "go", "rust", "c", "cpp"],
    },
    "TRIPLE_DES": {
        "pattern": r"3DES|DESede|Triple-?DES|TripleDES|DES3|des-ede3|EVP_des_ede3|DES\.MODE_CBC.*3",
        "risk_level": HIGH,
        "description": "Triple DES (3DES) detected. 3DES has an effective security of ~112 bits, further reduced by Grover's algorithm.",
        "replacement": "Replace with AES-256-GCM for authenticated symmetric encryption.",
        "languages": ["python", "java", "javascript", "go", "rust", "c", "cpp"],
    },
    "RC4": {
        "pattern": r"RC4|ARC4|ARCFOUR|rc4_encrypt|EVP_rc4|Cipher\.getInstance\s*\(\s*[\"']RC4",
        "risk_level": HIGH,
        "description": "RC4 stream cipher detected. RC4 has known statistical biases and is considered broken.",
        "replacement": "Replace with AES-256-GCM or ChaCha20-Poly1305 for authenticated encryption.",
        "languages": ["python", "java", "javascript", "go", "rust", "c", "cpp"],
    },
}
