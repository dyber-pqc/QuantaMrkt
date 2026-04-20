"""Tests for the pqc-audit CLI."""

from __future__ import annotations

import json
import os
from collections.abc import Callable

from click.testing import CliRunner
from quantumshield.identity.agent import AgentIdentity

from pqc_audit_log_fs.appender import LogAppender, RotationPolicy
from pqc_audit_log_fs.cli import main
from pqc_audit_log_fs.event import InferenceEvent


def _seed(
    log_dir: str,
    signer: AgentIdentity,
    factory: Callable[..., InferenceEvent],
    n: int = 5,
) -> None:
    app = LogAppender(
        log_dir, signer,
        rotation=RotationPolicy(max_events_per_segment=1000),
    )
    for _ in range(n):
        app.append(factory())
    app.close()


def test_verify_exits_0_for_good_log(
    signer_identity: AgentIdentity,
    tmp_log_dir: str,
    event_factory: Callable[..., InferenceEvent],
) -> None:
    _seed(tmp_log_dir, signer_identity, event_factory, n=3)
    runner = CliRunner()
    result = runner.invoke(main, ["verify", tmp_log_dir])
    assert result.exit_code == 0
    assert "OK" in result.output


def test_verify_exits_1_after_tamper(
    signer_identity: AgentIdentity,
    tmp_log_dir: str,
    event_factory: Callable[..., InferenceEvent],
) -> None:
    _seed(tmp_log_dir, signer_identity, event_factory, n=3)
    jsonl = os.path.join(tmp_log_dir, "segment-00001.log")
    with open(jsonl, "r", encoding="utf-8") as f:
        lines = f.readlines()
    first = json.loads(lines[0])
    first["decision_label"] = "TAMPERED"
    lines[0] = json.dumps(first, separators=(",", ":")) + "\n"
    with open(jsonl, "w", encoding="utf-8") as f:
        f.writelines(lines)
    runner = CliRunner()
    result = runner.invoke(main, ["verify", tmp_log_dir])
    assert result.exit_code == 1


def test_info_prints_segment_count(
    signer_identity: AgentIdentity,
    tmp_log_dir: str,
    event_factory: Callable[..., InferenceEvent],
) -> None:
    _seed(tmp_log_dir, signer_identity, event_factory, n=4)
    runner = CliRunner()
    result = runner.invoke(main, ["info", tmp_log_dir])
    assert result.exit_code == 0
    assert "segments: 1" in result.output
