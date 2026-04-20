"""Tests for TraceVerifier."""

from __future__ import annotations

import pytest

from pqc_reasoning_ledger import (
    ReasoningRecorder,
    SignatureVerificationError,
    TraceVerifier,
)


def _seal_small(recorder: ReasoningRecorder):
    recorder.record_observation("obs A")
    recorder.record_deduction("ded B")
    recorder.record_decision("final C")
    return recorder.seal()


def test_verify_valid_sealed_trace(
    sample_trace_started: ReasoningRecorder,
) -> None:
    sealed = _seal_small(sample_trace_started)
    result = TraceVerifier.verify(sealed)
    assert result.valid is True
    assert result.fully_verified is True
    assert result.error is None
    assert result.step_count == 3


def test_tamper_step_content_fails_chain_check(
    sample_trace_started: ReasoningRecorder,
) -> None:
    sealed = _seal_small(sample_trace_started)
    # Flip content on step 1 - step_hash stays the same but would no longer match
    # the recomputed hash because content_hash embedded in canonical_bytes changes.
    # However content_hash is what's hashed, not content, so we have to tamper
    # content_hash too to break the chain. Tamper content_hash directly.
    sealed.steps[0].content_hash = "0" * 64
    result = TraceVerifier.verify(sealed)
    assert result.chain_intact is False
    assert result.valid is False


def test_tamper_merkle_root_fails_merkle_check(
    sample_trace_started: ReasoningRecorder,
) -> None:
    sealed = _seal_small(sample_trace_started)
    sealed.merkle_root = "0" * 64
    result = TraceVerifier.verify(sealed)
    assert result.merkle_root_valid is False
    assert result.valid is False


def test_tamper_signature_fails_sig_check(
    sample_trace_started: ReasoningRecorder,
) -> None:
    sealed = _seal_small(sample_trace_started)
    # flip one byte of the signature hex
    orig = sealed.signature
    flipped = ("0" if orig[0] != "0" else "f") + orig[1:]
    sealed.signature = flipped
    result = TraceVerifier.verify(sealed)
    assert result.signature_valid is False
    assert result.valid is False


def test_verify_or_raise_raises_on_invalid(
    sample_trace_started: ReasoningRecorder,
) -> None:
    sealed = _seal_small(sample_trace_started)
    sealed.merkle_root = "0" * 64
    with pytest.raises(SignatureVerificationError):
        TraceVerifier.verify_or_raise(sealed)


def test_missing_signature_returns_invalid(
    sample_trace_started: ReasoningRecorder,
) -> None:
    sealed = _seal_small(sample_trace_started)
    sealed.signature = ""
    result = TraceVerifier.verify(sealed)
    assert result.signature_valid is False
    assert result.valid is False
    assert result.error is not None
