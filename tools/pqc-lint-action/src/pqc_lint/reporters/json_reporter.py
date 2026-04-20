"""JSON reporter."""

from __future__ import annotations

from pqc_lint.findings import ScanReport
from pqc_lint.reporters.base import Reporter


class JsonReporter(Reporter):
    format_name = "json"

    def render(self, report: ScanReport) -> str:
        return report.to_json()
