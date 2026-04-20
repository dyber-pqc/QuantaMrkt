"""Tests for the pqc-bpf CLI."""

from __future__ import annotations

import json

from click.testing import CliRunner

from pqc_ebpf_attestation.cli import main


def test_sign_creates_sig_json(tmp_path) -> None:
    runner = CliRunner()
    bpf_path = tmp_path / "trace.bpf.o"
    bpf_path.write_bytes(b"\x7fELF" + b"\x00" * 120)

    result = runner.invoke(
        main,
        [
            "sign",
            str(bpf_path),
            "--name",
            "trace-read",
            "--type",
            "kprobe",
            "--author",
            "ops-team",
        ],
    )
    assert result.exit_code == 0, result.output
    sig_path = tmp_path / "trace.bpf.o.sig.json"
    assert sig_path.exists()
    data = json.loads(sig_path.read_text())
    assert data["program"]["metadata"]["name"] == "trace-read"
    assert data["program"]["metadata"]["program_type"] == "kprobe"
    assert data["signer_did"].startswith("did:pqaid:")


def test_verify_ok_exit_code(tmp_path) -> None:
    runner = CliRunner()
    bpf_path = tmp_path / "program.bpf.o"
    bpf_path.write_bytes(b"\x7fELFpayload")

    sign_res = runner.invoke(
        main, ["sign", str(bpf_path), "--name", "p", "--type", "xdp"]
    )
    assert sign_res.exit_code == 0, sign_res.output

    sig_path = tmp_path / "program.bpf.o.sig.json"
    verify_res = runner.invoke(main, ["verify", str(sig_path)])
    assert verify_res.exit_code == 0, verify_res.output
    assert "signature VALID" in verify_res.output


def test_verify_fails_on_tampered(tmp_path) -> None:
    runner = CliRunner()
    bpf_path = tmp_path / "program.bpf.o"
    bpf_path.write_bytes(b"original-bytes")

    runner.invoke(main, ["sign", str(bpf_path), "--name", "p", "--type", "kprobe"])
    sig_path = tmp_path / "program.bpf.o.sig.json"
    data = json.loads(sig_path.read_text())
    # Swap the bytecode_hash to something wrong, keeping everything else.
    data["program"]["bytecode_hash"] = "00" * 32
    sig_path.write_text(json.dumps(data))

    verify_res = runner.invoke(main, ["verify", str(sig_path)])
    assert verify_res.exit_code == 1
    assert "FAIL" in verify_res.output


def test_info_shows_metadata(tmp_path) -> None:
    runner = CliRunner()
    bpf_path = tmp_path / "program.bpf.o"
    bpf_path.write_bytes(b"bytecode-here")

    runner.invoke(
        main,
        [
            "sign",
            str(bpf_path),
            "--name",
            "read-latency",
            "--type",
            "tracepoint",
            "--author",
            "sre",
        ],
    )
    sig_path = tmp_path / "program.bpf.o.sig.json"
    info_res = runner.invoke(main, ["info", str(sig_path)])
    assert info_res.exit_code == 0, info_res.output
    assert "read-latency" in info_res.output
    assert "tracepoint" in info_res.output
    assert "signer_did" in info_res.output
