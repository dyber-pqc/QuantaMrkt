"""Scanner tests for JavaScript fixtures."""

from __future__ import annotations

from pqc_lint.scanner import Scanner


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_node_crypto_rsa(scan_tmpdir):
    p = scan_tmpdir / "s.js"
    _write(p, (
        "const crypto = require('crypto');\n"
        "crypto.generateKeyPair('rsa', { modulusLength: 2048 });\n"
    ))
    report = Scanner().scan_path(str(scan_tmpdir))
    ids = {f.rule_id for f in report.findings}
    assert "PQC001" in ids


def test_web_crypto_ecdsa(scan_tmpdir):
    p = scan_tmpdir / "s.ts"
    _write(p, (
        "await crypto.subtle.generateKey(\n"
        "  { name: 'ECDSA', namedCurve: 'P-256' },\n"
        "  true, ['sign','verify'],\n"
        ");\n"
    ))
    report = Scanner().scan_path(str(scan_tmpdir))
    ids = {f.rule_id for f in report.findings}
    assert "PQC002" in ids


def test_node_crypto_sha1(scan_tmpdir):
    p = scan_tmpdir / "h.js"
    _write(p, "const crypto = require('crypto');\ncrypto.createHash('sha1');\n")
    report = Scanner().scan_path(str(scan_tmpdir))
    ids = {f.rule_id for f in report.findings}
    assert "PQC302" in ids
