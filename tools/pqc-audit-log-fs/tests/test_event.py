"""Tests for InferenceEvent."""

from __future__ import annotations

import hashlib

from pqc_audit_log_fs.event import InferenceEvent


def test_create_produces_stable_hashes() -> None:
    event = InferenceEvent.create(
        model_did="did:pqaid:abc",
        model_version="1.0",
        input_bytes=b"hello",
        output_bytes=b"world",
    )
    assert event.input_hash == hashlib.sha3_256(b"hello").hexdigest()
    assert event.output_hash == hashlib.sha3_256(b"world").hexdigest()
    # reasoning_chain_hash defaults empty when no reasoning_bytes provided
    assert event.reasoning_chain_hash == ""


def test_leaf_hash_deterministic() -> None:
    event = InferenceEvent(
        event_id="urn:evt:1",
        timestamp="2026-04-20T00:00:00+00:00",
        model_did="did:pqaid:m",
        model_version="1.0",
        input_hash="a" * 64,
        output_hash="b" * 64,
    )
    h1 = event.leaf_hash()
    h2 = event.leaf_hash()
    assert h1 == h2
    assert len(h1) == 64  # SHA3-256 hex


def test_canonical_bytes_deterministic() -> None:
    e1 = InferenceEvent(
        event_id="urn:evt:1",
        timestamp="2026-04-20T00:00:00+00:00",
        model_did="did:pqaid:m",
        model_version="1.0",
        input_hash="a" * 64,
        output_hash="b" * 64,
        metadata={"b": 1, "a": 2},
    )
    e2 = InferenceEvent(
        event_id="urn:evt:1",
        timestamp="2026-04-20T00:00:00+00:00",
        model_did="did:pqaid:m",
        model_version="1.0",
        input_hash="a" * 64,
        output_hash="b" * 64,
        metadata={"a": 2, "b": 1},
    )
    # metadata dicts declared in different order, but canonical_bytes is sorted
    assert e1.canonical_bytes() == e2.canonical_bytes()


def test_to_from_dict_roundtrip() -> None:
    original = InferenceEvent.create(
        model_did="did:pqaid:m",
        model_version="1.0",
        input_bytes=b"x",
        output_bytes=b"y",
        decision_label="approve",
        metadata={"k": "v"},
    )
    d = original.to_dict()
    restored = InferenceEvent.from_dict(d)
    assert restored == original
    assert restored.leaf_hash() == original.leaf_hash()
