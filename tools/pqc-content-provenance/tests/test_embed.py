"""Tests for embed/extract helpers."""

from __future__ import annotations

import pytest

from pqc_content_provenance import embed_manifest, extract_manifest
from pqc_content_provenance.errors import InvalidManifestError


def test_sidecar_roundtrip(signer, sample_manifest, sample_content) -> None:
    signed = signer.sign(sample_manifest)
    envelope = embed_manifest(sample_content, signed, mode="sidecar")
    assert isinstance(envelope, bytes)
    recovered_manifest, recovered_content = extract_manifest(envelope, mode="sidecar")
    assert recovered_content == sample_content
    assert recovered_manifest.manifest_id == signed.manifest_id
    assert recovered_manifest.signature == signed.signature


def test_text_header_roundtrip(signer, sample_manifest, sample_content) -> None:
    signed = signer.sign(sample_manifest)
    envelope = embed_manifest(sample_content, signed, mode="text-header")
    assert isinstance(envelope, bytes)
    recovered_manifest, recovered_content = extract_manifest(envelope, mode="text-header")
    assert recovered_content == sample_content
    assert recovered_manifest.manifest_id == signed.manifest_id


def test_text_header_missing_markers_raises() -> None:
    with pytest.raises(InvalidManifestError):
        extract_manifest(b"this blob has no provenance markers at all", mode="text-header")


def test_unknown_mode_raises(signer, sample_manifest, sample_content) -> None:
    signed = signer.sign(sample_manifest)
    with pytest.raises(ValueError):
        embed_manifest(sample_content, signed, mode="not-a-mode")
    with pytest.raises(ValueError):
        extract_manifest(b"irrelevant", mode="not-a-mode")


def test_sidecar_invalid_envelope_raises() -> None:
    with pytest.raises(InvalidManifestError):
        extract_manifest(b"{invalid json]]", mode="sidecar")
