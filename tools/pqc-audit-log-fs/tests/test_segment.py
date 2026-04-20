"""Tests for AuditSegment and SegmentHeader."""

from __future__ import annotations

from pqc_audit_log_fs.event import InferenceEvent
from pqc_audit_log_fs.segment import AuditSegment, SegmentHeader


def _make_event(i: int) -> InferenceEvent:
    return InferenceEvent.create(
        model_did="did:pqaid:m",
        model_version="1.0",
        input_bytes=f"in-{i}".encode(),
        output_bytes=f"out-{i}".encode(),
    )


def test_recompute_root_fills_fields() -> None:
    header = SegmentHeader(
        segment_id="segment-00001",
        segment_number=1,
        created_at="2026-04-20T00:00:00+00:00",
    )
    segment = AuditSegment(header=header, events=[_make_event(i) for i in range(4)])
    root = segment.recompute_root()
    assert len(root) == 64
    assert segment.header.event_count == 4
    assert segment.header.merkle_root == root


def test_header_roundtrip() -> None:
    h1 = SegmentHeader(
        segment_id="segment-00002",
        segment_number=2,
        created_at="2026-04-20T01:00:00+00:00",
        sealed_at="2026-04-20T02:00:00+00:00",
        event_count=3,
        merkle_root="deadbeef" * 8,
        previous_segment_root="cafef00d" * 8,
        log_id="urn:pqc-audit-log:xyz",
        signer_did="did:pqaid:signer",
        algorithm="ML-DSA-65",
        signature="ab" * 64,
        public_key="cd" * 64,
    )
    data = h1.to_dict()
    h2 = SegmentHeader.from_dict(data)
    assert h1 == h2


def test_canonical_bytes_deterministic() -> None:
    h = SegmentHeader(
        segment_id="segment-00001",
        segment_number=1,
        created_at="2026-04-20T00:00:00+00:00",
        sealed_at="2026-04-20T00:10:00+00:00",
        event_count=5,
        merkle_root="ab" * 32,
        previous_segment_root="",
        log_id="urn:pqc-audit-log:1",
    )
    b1 = h.canonical_bytes()
    b2 = h.canonical_bytes()
    assert b1 == b2
    # Signature/public_key fields are NOT part of the canonical payload.
    h.signature = "deadbeef"
    h.public_key = "cafe"
    assert h.canonical_bytes() == b1
