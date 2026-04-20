"""Tests for ManifestSigner: sign + verify flows."""

from __future__ import annotations

import pytest

from pqc_content_provenance import (
    ContentManifest,
    ManifestSigner,
)
from pqc_content_provenance.errors import ContentHashMismatchError


def test_sign_populates_signature_fields(signer, sample_manifest: ContentManifest) -> None:
    signed = signer.sign(sample_manifest)
    assert signed.signer_did != ""
    assert signed.signer_did.startswith("did:pqaid:")
    assert signed.algorithm != ""
    assert signed.signature != ""
    assert signed.public_key != ""
    assert signed.signed_at != ""


def test_verify_valid_manifest_returns_valid(signer, sample_manifest: ContentManifest) -> None:
    signed = signer.sign(sample_manifest)
    result = ManifestSigner.verify(signed)
    assert result.valid is True
    assert result.signature_match is True
    assert result.content_hash_match is True
    assert result.signer_did == signed.signer_did
    assert result.error is None


def test_verify_with_content_passes_when_match(
    signer, sample_manifest: ContentManifest, sample_content: bytes
) -> None:
    signed = signer.sign(sample_manifest)
    result = ManifestSigner.verify(signed, sample_content)
    assert result.valid is True
    assert result.content_hash_match is True


def test_verify_with_content_fails_when_mismatch(
    signer, sample_manifest: ContentManifest
) -> None:
    signed = signer.sign(sample_manifest)
    tampered_content = b"A totally different piece of text, not the original."
    result = ManifestSigner.verify(signed, tampered_content)
    assert result.valid is False
    assert result.content_hash_match is False
    # Signature itself is still valid (only the content-hash check fails)
    assert result.signature_match is True
    assert result.error is not None
    assert "content hash" in result.error


def test_verify_tampered_manifest_fails(signer, sample_manifest: ContentManifest) -> None:
    signed = signer.sign(sample_manifest)
    # Tamper: change the content_type after signing
    signed.content_type = "application/malicious"
    result = ManifestSigner.verify(signed)
    assert result.valid is False
    assert result.signature_match is False


def test_verify_wrong_algorithm_returns_error(signer, sample_manifest: ContentManifest) -> None:
    signed = signer.sign(sample_manifest)
    signed.algorithm = "NOT-A-REAL-ALG"
    result = ManifestSigner.verify(signed)
    assert result.valid is False
    assert result.signature_match is False
    assert result.error is not None
    assert "unknown algorithm" in result.error


def test_sign_and_raise_on_mismatch_raises_when_content_diff(
    signer, sample_manifest: ContentManifest
) -> None:
    different_content = b"This content is not what the manifest claims."
    with pytest.raises(ContentHashMismatchError):
        signer.sign_and_raise_on_mismatch(sample_manifest, different_content)


def test_sign_and_raise_on_mismatch_succeeds_when_match(
    signer, sample_manifest: ContentManifest, sample_content: bytes
) -> None:
    signed = signer.sign_and_raise_on_mismatch(sample_manifest, sample_content)
    assert signed.signature != ""
    result = ManifestSigner.verify(signed, sample_content)
    assert result.valid is True
