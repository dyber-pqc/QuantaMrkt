"""Output reporters for pqc-lint."""

from pqc_lint.reporters.base import Reporter
from pqc_lint.reporters.github import GitHubReporter
from pqc_lint.reporters.json_reporter import JsonReporter
from pqc_lint.reporters.sarif import SarifReporter
from pqc_lint.reporters.text import TextReporter

REPORTERS: dict[str, type[Reporter]] = {
    "text": TextReporter,
    "json": JsonReporter,
    "sarif": SarifReporter,
    "github": GitHubReporter,
}

__all__ = [
    "Reporter",
    "TextReporter",
    "JsonReporter",
    "SarifReporter",
    "GitHubReporter",
    "REPORTERS",
]
