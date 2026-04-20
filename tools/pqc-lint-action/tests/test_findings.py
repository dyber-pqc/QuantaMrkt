"""Tests for Finding / Severity / ScanReport."""

from __future__ import annotations

import pytest

from pqc_lint.findings import Finding, ScanReport, Severity


def test_severity_ordering():
    assert Severity.CRITICAL.order > Severity.HIGH.order
    assert Severity.HIGH.order > Severity.MEDIUM.order
    assert Severity.MEDIUM.order > Severity.LOW.order
    assert Severity.LOW.order > Severity.INFO.order


def test_severity_from_str():
    assert Severity.from_str("CRITICAL") is Severity.CRITICAL
    assert Severity.from_str("high") is Severity.HIGH
    assert Severity.from_str("MeDiUm") is Severity.MEDIUM
    with pytest.raises(ValueError):
        Severity.from_str("nope")


def test_finding_roundtrip():
    f = Finding(
        rule_id="PQC001",
        severity=Severity.CRITICAL,
        message="RSA found",
        file="foo.py",
        line=4,
        column=10,
        snippet="rsa.generate_private_key(...)",
        suggestion="Use ML-DSA",
        cwe="CWE-327",
        language="python",
    )
    data = f.to_dict()
    assert data["severity"] == "critical"
    assert data["rule_id"] == "PQC001"

    reloaded = Finding.from_dict(data)
    assert reloaded.rule_id == f.rule_id
    assert reloaded.severity is Severity.CRITICAL
    assert reloaded.file == f.file
    assert reloaded.line == f.line
    assert reloaded.snippet == f.snippet
    assert reloaded.cwe == f.cwe


def _mk_finding(severity: Severity, rule_id: str = "PQC001") -> Finding:
    return Finding(
        rule_id=rule_id, severity=severity, message="x",
        file="f.py", line=1,
    )


def test_scan_report_counts_by_severity():
    report = ScanReport()
    report.findings.extend([
        _mk_finding(Severity.CRITICAL),
        _mk_finding(Severity.CRITICAL),
        _mk_finding(Severity.HIGH),
        _mk_finding(Severity.MEDIUM),
    ])
    counts = report.counts_by_severity()
    assert counts["critical"] == 2
    assert counts["high"] == 1
    assert counts["medium"] == 1
    assert counts["low"] == 0


def test_scan_report_counts_by_rule():
    report = ScanReport()
    report.findings.extend([
        _mk_finding(Severity.CRITICAL, "PQC001"),
        _mk_finding(Severity.CRITICAL, "PQC001"),
        _mk_finding(Severity.HIGH, "PQC002"),
    ])
    counts = report.counts_by_rule()
    assert counts["PQC001"] == 2
    assert counts["PQC002"] == 1


def test_scan_report_has_failing_threshold():
    report = ScanReport()
    report.findings.append(_mk_finding(Severity.CRITICAL))
    assert report.has_failing(Severity.HIGH)
    assert report.has_failing(Severity.CRITICAL)
    # only medium, fail-on=high should NOT trigger
    report2 = ScanReport()
    report2.findings.append(_mk_finding(Severity.MEDIUM))
    assert not report2.has_failing(Severity.HIGH)
    assert report2.has_failing(Severity.LOW)
