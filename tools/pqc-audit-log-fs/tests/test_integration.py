"""End-to-end integration tests."""

from __future__ import annotations

import json
import os
from collections.abc import Callable

from quantumshield.identity.agent import AgentIdentity

from pqc_audit_log_fs.appender import LogAppender, RotationPolicy
from pqc_audit_log_fs.event import InferenceEvent
from pqc_audit_log_fs.reader import LogReader


def test_full_flow_25_events_produces_3_segments(
    signer_identity: AgentIdentity,
    tmp_log_dir: str,
    event_factory: Callable[..., InferenceEvent],
) -> None:
    app = LogAppender(
        tmp_log_dir, signer_identity,
        rotation=RotationPolicy(max_events_per_segment=10),
    )
    for _ in range(25):
        app.append(event_factory())
    # After 25 events with max=10: segments 1 and 2 are sealed; 5 events in
    # segment 3 (not yet sealed).
    assert os.path.exists(os.path.join(tmp_log_dir, "segment-00001.sig.json"))
    assert os.path.exists(os.path.join(tmp_log_dir, "segment-00002.sig.json"))
    assert not os.path.exists(os.path.join(tmp_log_dir, "segment-00003.sig.json"))
    app.close()
    # After close, segment 3 is also sealed
    assert os.path.exists(os.path.join(tmp_log_dir, "segment-00003.sig.json"))

    reader = LogReader(tmp_log_dir)
    assert reader.list_segments() == [1, 2, 3]
    ok, errors = reader.verify_chain()
    assert ok, f"unexpected errors: {errors}"


def test_tampering_flow_detected_by_verify_chain(
    signer_identity: AgentIdentity,
    tmp_log_dir: str,
    event_factory: Callable[..., InferenceEvent],
) -> None:
    app = LogAppender(
        tmp_log_dir, signer_identity,
        rotation=RotationPolicy(max_events_per_segment=5),
    )
    for _ in range(12):
        app.append(event_factory())
    app.close()

    # Tamper with segment 1's jsonl (changes merkle root vs declared)
    jsonl = os.path.join(tmp_log_dir, "segment-00001.log")
    with open(jsonl, "r", encoding="utf-8") as f:
        lines = f.readlines()
    first = json.loads(lines[0])
    first["decision_label"] = "FORGED"
    lines[0] = json.dumps(first, separators=(",", ":")) + "\n"
    with open(jsonl, "w", encoding="utf-8") as f:
        f.writelines(lines)

    reader = LogReader(tmp_log_dir)
    ok, errors = reader.verify_chain()
    assert not ok
    # At least one error identifies segment 1
    assert any("segment 1" in e or "segment 00001" in e for e in errors)
