"""Tests for output reporters."""

from __future__ import annotations

import json

from pqc_lint.findings import Finding, ScanReport, Severity
from pqc_lint.reporters import GitHubReporter, JsonReporter, SarifReporter, TextReporter


def _sample_report() -> ScanReport:
    report = ScanReport(scan_root=".", files_scanned=3)
    report.findings.append(Finding(
        rule_id="PQC001",
        severity=Severity.CRITICAL,
        message="RSA signature usage: broken by Shor's",
        file="pkg/auth.py",
        line=42,
        column=5,
        snippet="rsa.generate_private_key(65537, 2048)",
        suggestion="Use ML-DSA-65 (FIPS 204).",
        cwe="CWE-327",
        language="python",
    ))
    report.findings.append(Finding(
        rule_id="PQC301",
        severity=Severity.MEDIUM,
        message="MD5 hashing: broken",
        file="pkg/legacy.py",
        line=7,
        snippet="hashlib.md5(b'x')",
        suggestion="Use SHA3-256.",
        cwe="CWE-328",
        language="python",
    ))
    return report


def test_text_reporter_no_findings():
    report = ScanReport(scan_root=".")
    out = TextReporter().render(report)
    assert "PQC-clean" in out or "0 findings" in out


def test_text_reporter_with_findings():
    out = TextReporter().render(_sample_report())
    assert "PQC001" in out
    assert "PQC301" in out
    assert "auth.py" in out


def test_json_reporter_valid_json():
    data = json.loads(JsonReporter().render(_sample_report()))
    assert data["schema_version"] == "1.0"
    assert "findings" in data
    assert len(data["findings"]) == 2
    assert data["counts_by_severity"]["critical"] == 1
    assert data["counts_by_severity"]["medium"] == 1


def test_sarif_reporter_valid():
    sarif = json.loads(SarifReporter().render(_sample_report()))
    assert "$schema" in sarif
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "pqc-lint"
    assert isinstance(run["tool"]["driver"]["rules"], list)
    assert len(run["tool"]["driver"]["rules"]) > 0
    assert isinstance(run["results"], list)
    assert len(run["results"]) == 2


def test_sarif_reporter_maps_severity():
    sarif = json.loads(SarifReporter().render(_sample_report()))
    results = sarif["runs"][0]["results"]
    crit = next(r for r in results if r["ruleId"] == "PQC001")
    med = next(r for r in results if r["ruleId"] == "PQC301")
    assert crit["level"] == "error"
    assert med["level"] == "warning"


def test_github_reporter_emits_workflow_commands():
    out = GitHubReporter().render(_sample_report())
    lines = [line for line in out.splitlines() if line.strip()]
    # Every finding line should start with a workflow command
    finding_lines = [line for line in lines if line.startswith("::")]
    assert all(
        line.startswith("::error ") or line.startswith("::warning ") or line.startswith("::notice ")
        for line in finding_lines
    )
    # Must include at least one error for the critical finding
    assert any(line.startswith("::error ") for line in lines)
    assert any(line.startswith("::warning ") for line in lines)


def test_github_reporter_escapes_newlines_in_messages():
    report = ScanReport()
    report.findings.append(Finding(
        rule_id="PQC001",
        severity=Severity.CRITICAL,
        message="line one\nline two",
        file="f.py",
        line=1,
    ))
    out = GitHubReporter().render(report)
    # Newlines inside messages must be escaped as %0A — so the body of the first line
    # should not contain a raw embedded newline.
    first_line = out.splitlines()[0]
    assert "%0A" in first_line
