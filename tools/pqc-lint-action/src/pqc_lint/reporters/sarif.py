"""SARIF 2.1.0 reporter - compatible with GitHub code scanning."""

from __future__ import annotations

import json

from pqc_lint.findings import ScanReport, Severity
from pqc_lint.reporters.base import Reporter
from pqc_lint.rules import RULES

_SEVERITY_TO_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


class SarifReporter(Reporter):
    format_name = "sarif"

    def render(self, report: ScanReport) -> str:
        rules_payload = []
        for r in RULES:
            rules_payload.append({
                "id": r.id,
                "name": r.title.replace(" ", ""),
                "shortDescription": {"text": r.title},
                "fullDescription": {"text": r.message},
                "helpUri": "https://quantamrkt.com/tools/pqc-lint-action",
                "help": {"text": r.suggestion or r.message},
                "defaultConfiguration": {
                    "level": _SEVERITY_TO_SARIF_LEVEL[r.severity],
                },
                "properties": {
                    "tags": ["security", "post-quantum", "cryptography"],
                    "cwe": r.cwe or "",
                    "precision": "high",
                    "classical_primitive": r.classical_primitive,
                },
            })

        results = []
        for f in report.findings:
            results.append({
                "ruleId": f.rule_id,
                "level": _SEVERITY_TO_SARIF_LEVEL[f.severity],
                "message": {"text": f"{f.message} Suggestion: {f.suggestion}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": {
                            "startLine": f.line,
                            "startColumn": f.column,
                            "snippet": {"text": f.snippet or ""},
                        },
                    },
                }],
                "properties": {
                    "severity": f.severity.value,
                    "cwe": f.cwe or "",
                    "suggestion": f.suggestion,
                },
            })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "pqc-lint",
                        "version": "0.1.0",
                        "informationUri": "https://quantamrkt.com/tools/pqc-lint-action",
                        "rules": rules_payload,
                    },
                },
                "results": results,
                "columnKind": "utf16CodeUnits",
            }],
        }
        return json.dumps(sarif, indent=2)
