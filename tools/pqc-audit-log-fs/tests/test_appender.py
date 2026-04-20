"""Tests for LogAppender."""

from __future__ import annotations

import os
from collections.abc import Callable

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_audit_log_fs.appender import LogAppender, RotationPolicy
from pqc_audit_log_fs.errors import AppendToSealedSegmentError
from pqc_audit_log_fs.event import InferenceEvent


def test_append_writes_jsonl_no_seal_yet(
    signer_identity: AgentIdentity,
    tmp_log_dir: str,
    event_factory: Callable[..., InferenceEvent],
) -> None:
    app = LogAppender(
        tmp_log_dir, signer_identity,
        rotation=RotationPolicy(max_events_per_segment=100),
    )
    app.append(event_factory())
    app.append(event_factory())
    jsonl = os.path.join(tmp_log_dir, "segment-00001.log")
    sig = os.path.join(tmp_log_dir, "segment-00001.sig.json")
    assert os.path.exists(jsonl)
    assert not os.path.exists(sig)  # not sealed yet
    app.close()


def test_seal_current_segment_writes_sig(
    signer_identity: AgentIdentity,
    tmp_log_dir: str,
    event_factory: Callable[..., InferenceEvent],
) -> None:
    app = LogAppender(tmp_log_dir, signer_identity)
    app.append(event_factory())
    header = app.seal_current_segment()
    assert header is not None
    assert header.segment_number == 1
    assert len(header.merkle_root) == 64
    sig_path = os.path.join(tmp_log_dir, "segment-00001.sig.json")
    assert os.path.exists(sig_path)
    app.close()


def test_rotation_on_event_count(
    signer_identity: AgentIdentity,
    tmp_log_dir: str,
    event_factory: Callable[..., InferenceEvent],
) -> None:
    app = LogAppender(
        tmp_log_dir, signer_identity,
        rotation=RotationPolicy(max_events_per_segment=3),
    )
    for _ in range(3):
        app.append(event_factory())
    # Hitting 3 events triggers a seal
    assert os.path.exists(os.path.join(tmp_log_dir, "segment-00001.sig.json"))
    app.close()


def test_rotation_on_byte_threshold(
    signer_identity: AgentIdentity,
    tmp_log_dir: str,
    event_factory: Callable[..., InferenceEvent],
) -> None:
    app = LogAppender(
        tmp_log_dir, signer_identity,
        rotation=RotationPolicy(
            max_events_per_segment=100_000,
            max_bytes_per_segment=256,   # tiny
        ),
    )
    # A single event's JSONL line is > 256 bytes once metadata is present
    app.append(event_factory())
    app.append(event_factory())
    assert os.path.exists(os.path.join(tmp_log_dir, "segment-00001.sig.json"))
    app.close()


def test_append_after_close_raises(
    signer_identity: AgentIdentity,
    tmp_log_dir: str,
    event_factory: Callable[..., InferenceEvent],
) -> None:
    app = LogAppender(tmp_log_dir, signer_identity)
    app.append(event_factory())
    app.close()
    with pytest.raises(AppendToSealedSegmentError):
        app.append(event_factory())


def test_close_seals_final_segment(
    signer_identity: AgentIdentity,
    tmp_log_dir: str,
    event_factory: Callable[..., InferenceEvent],
) -> None:
    app = LogAppender(
        tmp_log_dir, signer_identity,
        rotation=RotationPolicy(max_events_per_segment=1000),
    )
    app.append(event_factory())
    app.append(event_factory())
    app.close()
    assert os.path.exists(os.path.join(tmp_log_dir, "segment-00001.sig.json"))


def test_reopen_continues_with_next_segment(
    signer_identity: AgentIdentity,
    tmp_log_dir: str,
    event_factory: Callable[..., InferenceEvent],
) -> None:
    # First session
    app1 = LogAppender(
        tmp_log_dir, signer_identity,
        rotation=RotationPolicy(max_events_per_segment=2),
    )
    app1.append(event_factory())
    app1.append(event_factory())  # rotate -> seg 1 sealed
    app1.close()
    # Re-open
    app2 = LogAppender(
        tmp_log_dir, signer_identity,
        rotation=RotationPolicy(max_events_per_segment=2),
    )
    # Next segment number should be 2
    assert app2._current_segment_number == 2
    assert app2._previous_segment_root != ""
    app2.append(event_factory())
    app2.close()
    assert os.path.exists(os.path.join(tmp_log_dir, "segment-00002.sig.json"))
