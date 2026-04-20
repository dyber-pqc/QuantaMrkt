"""Scanner tests for Python fixtures."""

from __future__ import annotations

import os

from pqc_lint.scanner import Scanner


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_scanner_detects_rsa_generate(scan_tmpdir, sample_python_rsa):
    p = scan_tmpdir / "rsa_sample.py"
    _write(p, sample_python_rsa)
    report = Scanner().scan_path(str(scan_tmpdir))
    ids = {f.rule_id for f in report.findings}
    assert "PQC001" in ids


def test_scanner_detects_ecdsa(scan_tmpdir, sample_python_ecdsa):
    p = scan_tmpdir / "ec_sample.py"
    _write(p, sample_python_ecdsa)
    report = Scanner().scan_path(str(scan_tmpdir))
    ids = {f.rule_id for f in report.findings}
    assert "PQC002" in ids


def test_scanner_detects_ed25519(scan_tmpdir):
    p = scan_tmpdir / "ed.py"
    _write(p, (
        "from cryptography.hazmat.primitives.asymmetric import ed25519\n"
        "k = ed25519.Ed25519PrivateKey.generate()\n"
    ))
    report = Scanner().scan_path(str(scan_tmpdir))
    ids = {f.rule_id for f in report.findings}
    assert "PQC003" in ids


def test_scanner_detects_md5(scan_tmpdir):
    p = scan_tmpdir / "h.py"
    _write(p, "import hashlib\nd = hashlib.md5(b'x').hexdigest()\n")
    report = Scanner().scan_path(str(scan_tmpdir))
    ids = {f.rule_id for f in report.findings}
    assert "PQC301" in ids


def test_scanner_clean_file_no_findings(scan_tmpdir, sample_python_clean):
    p = scan_tmpdir / "clean.py"
    _write(p, sample_python_clean)
    report = Scanner().scan_path(str(scan_tmpdir))
    assert report.findings == []
    assert report.files_scanned == 1


def test_scanner_excludes_directories(scan_tmpdir, sample_python_rsa):
    node = scan_tmpdir / "node_modules" / "evil.py"
    _write(node, sample_python_rsa)
    report = Scanner().scan_path(str(scan_tmpdir))
    # File inside node_modules should not produce findings
    paths = {f.file for f in report.findings}
    assert not any("node_modules" in p for p in paths)


def test_scanner_respects_language_filter(scan_tmpdir, sample_python_rsa):
    p = scan_tmpdir / "x.py"
    _write(p, sample_python_rsa)
    report = Scanner(languages=("go",)).scan_path(str(scan_tmpdir))
    assert report.findings == []


def test_scanner_handles_nonexistent_file():
    scanner = Scanner()
    findings = scanner.scan_file("/totally/not/a/real/path.py")
    assert findings == []


def test_scanner_skips_huge_files(scan_tmpdir):
    p = scan_tmpdir / "big.py"
    # Write >2MB of data. The pattern IS inside, but file should be skipped.
    content = (
        "import cryptography\n"
        + ("x = 1" + " " * 20 + "\n") * 100_000
        + "rsa.generate_private_key()\n"
    )
    _write(p, content)
    assert os.path.getsize(p) > 2 * 1024 * 1024
    report = Scanner().scan_path(str(scan_tmpdir))
    assert report.findings == []
