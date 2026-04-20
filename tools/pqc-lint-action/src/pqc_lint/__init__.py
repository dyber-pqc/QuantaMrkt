"""PQC Lint — find classical cryptography in source code and suggest PQC replacements."""

from pqc_lint.findings import Finding, ScanReport, Severity
from pqc_lint.rules import RULES, Rule, get_rules_for_language
from pqc_lint.scanner import Scanner
from pqc_lint.suggestions import suggest_replacement

__version__ = "0.1.0"
__all__ = [
    "Finding",
    "Severity",
    "ScanReport",
    "Rule",
    "RULES",
    "get_rules_for_language",
    "Scanner",
    "suggest_replacement",
]
