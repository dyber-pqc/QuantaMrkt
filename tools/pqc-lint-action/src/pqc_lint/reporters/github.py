"""GitHub Actions workflow-command reporter.

Emits `::error file=...,line=...::msg` and `::warning ...::msg` lines that
GitHub Actions auto-renders as annotations on PR diffs.
"""

from __future__ import annotations

from io import StringIO

from pqc_lint.findings import ScanReport, Severity
from pqc_lint.reporters.base import Reporter

_SEVERITY_TO_COMMAND = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "notice",
    Severity.INFO: "notice",
}


def _escape(value: str) -> str:
    return (
        value.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
    )


class GitHubReporter(Reporter):
    format_name = "github"

    def render(self, report: ScanReport) -> str:
        buf = StringIO()
        for f in report.findings:
            cmd = _SEVERITY_TO_COMMAND[f.severity]
            title = _escape(f"{f.rule_id}: {f.severity.value.upper()}")
            message = _escape(f"{f.message} Suggestion: {f.suggestion}")
            buf.write(
                f"::{cmd} file={f.file},line={f.line},col={f.column},title={title}::{message}\n"
            )
        counts = report.counts_by_severity()
        buf.write(
            f"::notice title=pqc-lint summary::"
            f"Scanned {report.files_scanned} files. "
            f"Found {len(report.findings)} issues "
            f"(critical={counts['critical']}, high={counts['high']}, "
            f"medium={counts['medium']}, low={counts['low']}).\n"
        )
        return buf.getvalue()
