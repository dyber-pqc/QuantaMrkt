"""Rule catalog for pqc-lint."""

from __future__ import annotations

from dataclasses import dataclass

from pqc_lint.findings import Severity
from pqc_lint.suggestions import suggest_replacement


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    classical_primitive: str          # RSA-PSS, ECDSA, DH, etc.
    title: str                        # short title
    message: str                      # detailed message
    languages: tuple[str, ...]        # languages this rule applies to
    cwe: str | None = None

    @property
    def suggestion(self) -> str:
        return suggest_replacement(self.classical_primitive)


# -------------------------------------------------------------------------
# Rules
# -------------------------------------------------------------------------
# ID scheme:
#   PQC001-099  - signature schemes (RSA, ECDSA, Ed25519, DSA)
#   PQC100-199  - key exchange (DH, ECDH, X25519)
#   PQC200-299  - encryption (RSA-OAEP, RSA-PKCS1)
#   PQC300-399  - weak hashes (MD5, SHA-1)

RULES: tuple[Rule, ...] = (
    # -- Signatures (broken by Shor's) --
    Rule(
        id="PQC001", severity=Severity.CRITICAL,
        classical_primitive="RSA-signing",
        title="RSA signature usage",
        message="RSA signatures are broken by Shor's algorithm on a sufficiently large quantum computer.",
        languages=("python", "javascript", "go", "rust", "java", "c"),
        cwe="CWE-327",
    ),
    Rule(
        id="PQC002", severity=Severity.CRITICAL,
        classical_primitive="ECDSA",
        title="ECDSA signature usage",
        message="ECDSA signatures are broken by Shor's algorithm. All elliptic-curve signatures are quantum-vulnerable.",
        languages=("python", "javascript", "go", "rust", "java", "c"),
        cwe="CWE-327",
    ),
    Rule(
        id="PQC003", severity=Severity.HIGH,
        classical_primitive="Ed25519",
        title="Ed25519 signature usage",
        message="Ed25519 is a classical EC signature - broken by Shor's algorithm. Consider PQC alternative.",
        languages=("python", "javascript", "go", "rust", "java"),
        cwe="CWE-327",
    ),
    Rule(
        id="PQC004", severity=Severity.HIGH,
        classical_primitive="DSA",
        title="DSA signature usage",
        message="DSA is broken by Shor's algorithm and deprecated even in classical settings.",
        languages=("python", "java"),
        cwe="CWE-327",
    ),

    # -- Key exchange (broken by Shor's) --
    Rule(
        id="PQC101", severity=Severity.CRITICAL,
        classical_primitive="ECDH",
        title="ECDH key exchange",
        message="Elliptic Curve Diffie-Hellman key exchange is broken by Shor's algorithm.",
        languages=("python", "javascript", "go", "rust", "java", "c"),
        cwe="CWE-327",
    ),
    Rule(
        id="PQC102", severity=Severity.CRITICAL,
        classical_primitive="DH",
        title="Finite-field Diffie-Hellman",
        message="Classical Diffie-Hellman is broken by Shor's algorithm.",
        languages=("python", "javascript", "go", "rust", "java", "c"),
        cwe="CWE-327",
    ),
    Rule(
        id="PQC103", severity=Severity.HIGH,
        classical_primitive="X25519",
        title="X25519 key agreement",
        message="X25519 is a classical EC key agreement - broken by Shor's algorithm.",
        languages=("python", "javascript", "go", "rust", "java"),
        cwe="CWE-327",
    ),

    # -- Encryption --
    Rule(
        id="PQC201", severity=Severity.CRITICAL,
        classical_primitive="RSA-OAEP",
        title="RSA-OAEP encryption",
        message="RSA-OAEP encryption is broken by Shor's algorithm. All data encrypted today may be decrypted once CRQC exists (HNDL).",
        languages=("python", "javascript", "go", "rust", "java", "c"),
        cwe="CWE-327",
    ),
    Rule(
        id="PQC202", severity=Severity.CRITICAL,
        classical_primitive="RSA-PKCS1v15",
        title="RSA PKCS#1v1.5 encryption",
        message="RSA PKCS#1v1.5 is broken by Shor's algorithm AND has padding oracle vulnerabilities in classical settings.",
        languages=("python", "javascript", "go", "rust", "java", "c"),
        cwe="CWE-327",
    ),

    # -- Weak hashes --
    Rule(
        id="PQC301", severity=Severity.MEDIUM,
        classical_primitive="MD5",
        title="MD5 hashing",
        message="MD5 is cryptographically broken. Use SHA3 family.",
        languages=("python", "javascript", "go", "rust", "java", "c"),
        cwe="CWE-328",
    ),
    Rule(
        id="PQC302", severity=Severity.MEDIUM,
        classical_primitive="SHA1",
        title="SHA-1 hashing",
        message="SHA-1 is broken (SHAttered). Use SHA3 for quantum-safe hashing.",
        languages=("python", "javascript", "go", "rust", "java", "c"),
        cwe="CWE-328",
    ),
)


RULE_BY_ID: dict[str, Rule] = {r.id: r for r in RULES}


def get_rule(rule_id: str) -> Rule:
    return RULE_BY_ID[rule_id]


def get_rules_for_language(language: str) -> list[Rule]:
    return [r for r in RULES if language in r.languages]
