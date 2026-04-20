"""Scanner tests for Go fixtures."""

from __future__ import annotations

from pqc_lint.scanner import Scanner


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_go_rsa_import(scan_tmpdir):
    p = scan_tmpdir / "s.go"
    _write(p, (
        "package main\n\n"
        "import (\n"
        "    \"crypto/rand\"\n"
        "    \"crypto/rsa\"\n"
        ")\n\n"
        "func main() { _, _ = rsa.GenerateKey(rand.Reader, 2048) }\n"
    ))
    report = Scanner().scan_path(str(scan_tmpdir))
    ids = {f.rule_id for f in report.findings}
    assert "PQC001" in ids


def test_go_ecdsa_generate(scan_tmpdir):
    p = scan_tmpdir / "s.go"
    _write(p, (
        "package main\n\n"
        "import (\n"
        "    \"crypto/ecdsa\"\n"
        "    \"crypto/elliptic\"\n"
        "    \"crypto/rand\"\n"
        ")\n\n"
        "func main() { _, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }\n"
    ))
    report = Scanner().scan_path(str(scan_tmpdir))
    ids = {f.rule_id for f in report.findings}
    assert "PQC002" in ids


def test_go_md5_package_import(scan_tmpdir):
    p = scan_tmpdir / "s.go"
    _write(p, (
        "package main\n"
        "import \"crypto/md5\"\n"
        "func main() { _ = md5.New() }\n"
    ))
    report = Scanner().scan_path(str(scan_tmpdir))
    ids = {f.rule_id for f in report.findings}
    assert "PQC301" in ids
