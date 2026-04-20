"""Tests for InclusionProver."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_audit_log_fs.appender import LogAppender, RotationPolicy
from pqc_audit_log_fs.errors import SegmentNotFoundError
from pqc_audit_log_fs.event import InferenceEvent
from pqc_audit_log_fs.prover import InclusionProver
from pqc_audit_log_fs.reader import LogReader


def _seed_segment(
    log_dir: str,
    signer: AgentIdentity,
    factory: Callable[..., InferenceEvent],
    n: int = 8,
) -> list[InferenceEvent]:
    events = [factory() for _ in range(n)]
    app = LogAppender(
        log_dir, signer,
        rotation=RotationPolicy(max_events_per_segment=1000),
    )
    for e in events:
        app.append(e)
    app.close()
    return events


def test_prove_event_returns_valid_proof(
    signer_identity: AgentIdentity,
    tmp_log_dir: str,
    event_factory: Callable[..., InferenceEvent],
) -> None:
    events = _seed_segment(tmp_log_dir, signer_identity, event_factory, n=6)
    reader = LogReader(tmp_log_dir)
    prover = InclusionProver(reader)
    proof = prover.prove_event(1, events[3].event_id)
    assert proof.index == 3
    assert proof.tree_size == 6


def test_verify_proof_passes(
    signer_identity: AgentIdentity,
    tmp_log_dir: str,
    event_factory: Callable[..., InferenceEvent],
) -> None:
    events = _seed_segment(tmp_log_dir, signer_identity, event_factory, n=10)
    reader = LogReader(tmp_log_dir)
    prover = InclusionProver(reader)
    target = events[7]
    proof = prover.prove_event(1, target.event_id)
    assert InclusionProver.verify_proof(target, proof) is True


def test_verify_proof_fails_for_tampered_event(
    signer_identity: AgentIdentity,
    tmp_log_dir: str,
    event_factory: Callable[..., InferenceEvent],
) -> None:
    events = _seed_segment(tmp_log_dir, signer_identity, event_factory, n=5)
    reader = LogReader(tmp_log_dir)
    prover = InclusionProver(reader)
    target = events[2]
    proof = prover.prove_event(1, target.event_id)
    # Mutate the event after the proof was generated
    tampered = InferenceEvent.from_dict(target.to_dict())
    tampered.decision_label = "FORGED"
    assert InclusionProver.verify_proof(tampered, proof) is False


def test_missing_event_raises(
    signer_identity: AgentIdentity,
    tmp_log_dir: str,
    event_factory: Callable[..., InferenceEvent],
) -> None:
    _seed_segment(tmp_log_dir, signer_identity, event_factory, n=3)
    reader = LogReader(tmp_log_dir)
    prover = InclusionProver(reader)
    with pytest.raises(SegmentNotFoundError):
        prover.prove_event(1, "urn:pqc-audit-evt:does-not-exist")
