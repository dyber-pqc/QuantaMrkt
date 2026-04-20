"""Tests for ProvenanceChain."""

from __future__ import annotations

import pytest

from pqc_content_provenance import (
    AIGeneratedAssertion,
    ContentManifest,
    GenerationContext,
    ManifestSigner,
    ModelAttribution,
    ProvenanceChain,
)
from pqc_content_provenance.errors import ChainBrokenError


def _build_manifest(
    content: bytes,
    attribution: ModelAttribution,
    context: GenerationContext,
    previous_manifest_id: str | None = None,
) -> ContentManifest:
    return ContentManifest.create(
        content=content,
        content_type="text/plain",
        model_attribution=attribution,
        generation_context=context,
        assertions=[AIGeneratedAssertion(model_name=attribution.model_name)],
        previous_manifest_id=previous_manifest_id,
    )


def test_chain_single_link_verifies(
    signer, sample_manifest: ContentManifest
) -> None:
    signed = signer.sign(sample_manifest)
    chain = ProvenanceChain()
    chain.add(signed)
    ok, errors = chain.verify_chain()
    assert ok is True
    assert errors == []


def test_chain_multiple_links_verifies(
    signer, sample_attribution, sample_context
) -> None:
    m1 = _build_manifest(b"original draft", sample_attribution, sample_context)
    s1 = signer.sign(m1)

    m2 = _build_manifest(
        b"first edit", sample_attribution, sample_context, previous_manifest_id=s1.manifest_id
    )
    s2 = signer.sign(m2)

    m3 = _build_manifest(
        b"second edit", sample_attribution, sample_context, previous_manifest_id=s2.manifest_id
    )
    s3 = signer.sign(m3)

    chain = ProvenanceChain()
    chain.add(s1)
    chain.add(s2)
    chain.add(s3)

    ok, errors = chain.verify_chain()
    assert ok is True
    assert errors == []
    assert len(chain.links) == 3


def test_chain_broken_when_previous_id_mismatch(
    signer, sample_attribution, sample_context
) -> None:
    m1 = _build_manifest(b"original", sample_attribution, sample_context)
    s1 = signer.sign(m1)

    # Deliberately wrong previous_manifest_id
    m2 = _build_manifest(
        b"bogus edit",
        sample_attribution,
        sample_context,
        previous_manifest_id="urn:pqc-prov:not-a-real-id",
    )
    s2 = signer.sign(m2)

    chain = ProvenanceChain()
    chain.add(s1)
    with pytest.raises(ChainBrokenError):
        chain.add(s2)


def test_chain_roundtrip_to_dicts(
    signer, sample_attribution, sample_context
) -> None:
    m1 = _build_manifest(b"original", sample_attribution, sample_context)
    s1 = signer.sign(m1)
    m2 = _build_manifest(
        b"edit", sample_attribution, sample_context, previous_manifest_id=s1.manifest_id
    )
    s2 = signer.sign(m2)

    chain = ProvenanceChain()
    chain.add(s1)
    chain.add(s2)

    dicts = chain.to_dicts()
    assert len(dicts) == 2
    restored = ProvenanceChain.from_dicts(dicts)
    assert len(restored.links) == 2
    ok, errors = restored.verify_chain()
    assert ok is True
    assert errors == []


def test_chain_detects_tampered_signature_on_verify(
    signer, sample_attribution, sample_context
) -> None:
    m1 = _build_manifest(b"original", sample_attribution, sample_context)
    s1 = signer.sign(m1)
    chain = ProvenanceChain()
    chain.add(s1)
    # Tamper after adding
    s1.content_type = "application/malicious"
    ok, errors = chain.verify_chain()
    assert ok is False
    assert any("signature invalid" in e for e in errors)


def test_chain_verify_reports_link_break_from_raw_dicts(
    signer, sample_attribution, sample_context
) -> None:
    # from_dicts bypasses add(), so verify_chain must also report link breaks
    m1 = _build_manifest(b"a", sample_attribution, sample_context)
    s1 = signer.sign(m1)
    m2 = _build_manifest(
        b"b",
        sample_attribution,
        sample_context,
        previous_manifest_id="urn:pqc-prov:unrelated",
    )
    s2 = signer.sign(m2)
    chain = ProvenanceChain.from_dicts([s1.to_dict(), s2.to_dict()])
    _ = ManifestSigner  # keep imported name referenced for linter clarity
    ok, errors = chain.verify_chain()
    assert ok is False
    assert any("link break" in e for e in errors)
