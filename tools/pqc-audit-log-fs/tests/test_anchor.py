"""Tests for MerkleAnchor and NullAnchorSink."""

from __future__ import annotations

from pqc_audit_log_fs.anchor import MerkleAnchor, NullAnchorSink


def test_null_sink_records_publishes() -> None:
    sink = NullAnchorSink()
    receipt = sink.publish("urn:log:1", 1, "ab" * 32)
    assert receipt == "null-receipt-1"
    assert sink.received == [("urn:log:1", 1, "ab" * 32)]


def test_merkle_anchor_stores_receipt() -> None:
    sink = NullAnchorSink()
    anchor = MerkleAnchor(sink=sink)
    r1 = anchor.anchor_segment("urn:log:1", 1, "aa" * 32)
    r2 = anchor.anchor_segment("urn:log:1", 2, "bb" * 32)
    assert anchor.published == {1: r1, 2: r2}
    assert r1 != r2
