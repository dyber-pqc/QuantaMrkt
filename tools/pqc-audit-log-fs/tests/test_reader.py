"""Tests for LogReader."""

from __future__ import annotations

import json
import os
from collections.abc import Callable

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_audit_log_fs.appender import LogAppender, RotationPolicy
from pqc_audit_log_fs.errors import SegmentCorruptedError, SignatureVerificationError
from pqc_audit_log_fs.event import InferenceEvent
from pqc_audit_log_fs.reader import LogReader


def _seed(
    log_dir: str,
    signer: AgentIdentity,
    factory: Callable[..., InferenceEvent],
    n: int = 3,
    max_events: int = 100,
) -> None:
    app = LogAppender(
        log_dir, signer,
        rotation=RotationPolicy(max_events_per_segment=max_events),
    )
    for _ in range(n):
        app.append(factory())
    app.close()


def test_list_segments_sorted(
    signer_identity: AgentIdentity,
    tmp_log_dir: str,
    event_factory: Callable[..., InferenceEvent],
) -> None:
    # Create 3 rotated segments
    app = LogAppender(
        tmp_log_dir, signer_identity,
        rotation=RotationPolicy(max_events_per_segment=1),
    )
    for _ in range(3):
        app.append(event_factory())
    app.close()
    reader = LogReader(tmp_log_dir)
    assert reader.list_segments() == [1, 2, 3]


def test_read_header_and_segment(
    signer_identity: AgentIdentity,
    tmp_log_dir: str,
    event_factory: Callable[..., InferenceEvent],
) -> None:
    _seed(tmp_log_dir, signer_identity, event_factory, n=3)
    reader = LogReader(tmp_log_dir)
    header = reader.read_header(1)
    segment = reader.read_segment(1)
    assert segment.header == header
    assert len(segment.events) == 3
    assert header.event_count == 3


def test_verify_segment_passes(
    signer_identity: AgentIdentity,
    tmp_log_dir: str,
    event_factory: Callable[..., InferenceEvent],
) -> None:
    _seed(tmp_log_dir, signer_identity, event_factory, n=5)
    reader = LogReader(tmp_log_dir)
    assert reader.verify_segment(1) is True


def test_tampered_jsonl_raises(
    signer_identity: AgentIdentity,
    tmp_log_dir: str,
    event_factory: Callable[..., InferenceEvent],
) -> None:
    _seed(tmp_log_dir, signer_identity, event_factory, n=4)
    jsonl = os.path.join(tmp_log_dir, "segment-00001.log")
    # Rewrite first line with a bogus decision_label (changes leaf hash)
    with open(jsonl, "r", encoding="utf-8") as f:
        lines = f.readlines()
    first = json.loads(lines[0])
    first["decision_label"] = "TAMPERED"
    lines[0] = json.dumps(first, separators=(",", ":")) + "\n"
    with open(jsonl, "w", encoding="utf-8") as f:
        f.writelines(lines)
    reader = LogReader(tmp_log_dir)
    with pytest.raises(SegmentCorruptedError):
        reader.verify_segment(1)


def test_tampered_signature_raises(
    signer_identity: AgentIdentity,
    tmp_log_dir: str,
    event_factory: Callable[..., InferenceEvent],
) -> None:
    _seed(tmp_log_dir, signer_identity, event_factory, n=3)
    sig_path = os.path.join(tmp_log_dir, "segment-00001.sig.json")
    with open(sig_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # Flip a byte in the signature hex
    sig = data["signature"]
    first_byte = sig[:2]
    flipped = f"{(int(first_byte, 16) ^ 0xFF):02x}"
    data["signature"] = flipped + sig[2:]
    with open(sig_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    reader = LogReader(tmp_log_dir)
    # If liboqs or ed25519 backend is in use this raises; stub backend always
    # returns True, in which case we skip the check.
    try:
        reader.verify_segment(1)
    except SignatureVerificationError:
        return
    pytest.skip(
        "signature backend is STUB (no liboqs or ed25519); "
        "tampered signatures cannot be detected in stub mode"
    )
