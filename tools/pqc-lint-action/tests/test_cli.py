"""CLI tests using click's CliRunner."""

from __future__ import annotations

import json

from click.testing import CliRunner

from pqc_lint.cli import main


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_rules_command_lists_rules():
    runner = CliRunner()
    result = runner.invoke(main, ["rules"])
    assert result.exit_code == 0
    assert "PQC001" in result.output
    assert "PQC301" in result.output


def test_scan_clean_dir_exits_zero(tmp_path):
    _write(tmp_path / "clean.py", "def add(a, b):\n    return a + b\n")
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path)])
    assert result.exit_code == 0


def test_scan_finds_rsa_exits_one_with_fail_on_high(tmp_path):
    _write(tmp_path / "bad.py", (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    ))
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--fail-on", "high"])
    assert result.exit_code == 1


def test_scan_finds_medium_exits_zero_with_fail_on_critical(tmp_path):
    # MD5 is medium severity. --fail-on critical should NOT fail.
    _write(tmp_path / "h.py", "import hashlib\nhashlib.md5(b'x')\n")
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--fail-on", "critical"])
    assert result.exit_code == 0


def test_scan_json_output(tmp_path):
    _write(tmp_path / "bad.py", (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "k = rsa.generate_private_key(65537, 2048)\n"
    ))
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--format", "json", "--fail-on", "info"])
    # parse stdout as JSON
    data = json.loads(result.output)
    assert data["schema_version"] == "1.0"
    assert len(data["findings"]) > 0


def test_scan_sarif_output(tmp_path):
    _write(tmp_path / "bad.py", (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "k = rsa.generate_private_key(65537, 2048)\n"
    ))
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--format", "sarif", "--fail-on", "info"])
    data = json.loads(result.output)
    assert "$schema" in data
    assert data["version"] == "2.1.0"
