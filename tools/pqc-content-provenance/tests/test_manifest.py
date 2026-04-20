"""Tests for ContentManifest and its helpers."""

from __future__ import annotations

import pytest

from pqc_content_provenance import (
    AIGeneratedAssertion,
    ContentManifest,
    GenerationContext,
    ModelAttribution,
    UsageAssertion,
)
from pqc_content_provenance.errors import InvalidManifestError, UnknownAssertionError


def test_compute_content_hash_deterministic() -> None:
    data = b"hello, world"
    h1 = ContentManifest.compute_content_hash(data)
    h2 = ContentManifest.compute_content_hash(data)
    assert h1 == h2
    assert len(h1) == 64
    # Different content yields different hash
    assert ContentManifest.compute_content_hash(b"other") != h1


def test_create_sets_required_fields(sample_manifest: ContentManifest) -> None:
    m = sample_manifest
    assert m.manifest_id.startswith("urn:pqc-prov:")
    assert len(m.content_hash) == 64
    assert m.content_type == "text/plain"
    assert m.content_size > 0
    assert m.created_at != ""
    assert m.model_attribution.model_name == "Llama-3-8B-Instruct"
    assert len(m.assertions) == 2
    # Signature fields start empty (unsigned)
    assert m.signature == ""
    assert m.signer_did == ""


def test_to_dict_from_dict_roundtrip(sample_manifest: ContentManifest) -> None:
    # Fill signature-ish fields so roundtrip preserves them
    sample_manifest.signer_did = "did:pqaid:abc"
    sample_manifest.algorithm = "ML-DSA-65"
    sample_manifest.signature = "deadbeef"
    sample_manifest.public_key = "cafebabe"
    sample_manifest.signed_at = "2026-04-20T12:34:56+00:00"
    sample_manifest.previous_manifest_id = "urn:pqc-prov:prev"

    d = sample_manifest.to_dict()
    restored = ContentManifest.from_dict(d)

    assert restored.manifest_id == sample_manifest.manifest_id
    assert restored.content_hash == sample_manifest.content_hash
    assert restored.content_type == sample_manifest.content_type
    assert restored.content_size == sample_manifest.content_size
    assert restored.created_at == sample_manifest.created_at
    assert restored.previous_manifest_id == sample_manifest.previous_manifest_id
    assert restored.signer_did == sample_manifest.signer_did
    assert restored.algorithm == sample_manifest.algorithm
    assert restored.signature == sample_manifest.signature
    assert restored.public_key == sample_manifest.public_key
    assert restored.signed_at == sample_manifest.signed_at
    assert restored.model_attribution.model_did == sample_manifest.model_attribution.model_did
    assert restored.generation_context.prompt_hash == sample_manifest.generation_context.prompt_hash
    assert len(restored.assertions) == len(sample_manifest.assertions)
    # Assertion types preserved
    labels = {a.label for a in restored.assertions}
    assert "c2pa.ai_generated" in labels
    assert "c2pa.usage" in labels


def test_from_json_raises_on_invalid_json() -> None:
    with pytest.raises(InvalidManifestError):
        ContentManifest.from_json("{not valid json")


def test_from_dict_raises_on_unknown_assertion(sample_manifest: ContentManifest) -> None:
    d = sample_manifest.to_dict()
    d["assertions"].append({"label": "c2pa.unknown_type", "foo": "bar"})
    with pytest.raises(UnknownAssertionError):
        ContentManifest.from_dict(d)


def test_canonical_bytes_stable(sample_manifest: ContentManifest) -> None:
    a = sample_manifest.canonical_bytes()
    b = sample_manifest.canonical_bytes()
    assert a == b
    # Same logical content -> same bytes regardless of dict ordering
    m2 = ContentManifest(
        manifest_id=sample_manifest.manifest_id,
        content_hash=sample_manifest.content_hash,
        content_type=sample_manifest.content_type,
        content_size=sample_manifest.content_size,
        model_attribution=ModelAttribution(
            model_did=sample_manifest.model_attribution.model_did,
            model_name=sample_manifest.model_attribution.model_name,
            model_version=sample_manifest.model_attribution.model_version,
            registry_url=sample_manifest.model_attribution.registry_url,
            model_manifest_hash=sample_manifest.model_attribution.model_manifest_hash,
        ),
        generation_context=GenerationContext(
            prompt_hash=sample_manifest.generation_context.prompt_hash,
            input_content_hashes=list(sample_manifest.generation_context.input_content_hashes),
            parameters=dict(sample_manifest.generation_context.parameters),
            generated_at=sample_manifest.generation_context.generated_at,
        ),
        assertions=[
            AIGeneratedAssertion(
                model_name="Llama-3-8B-Instruct",
                model_version="1.0",
                generator_type="text",
            ),
            UsageAssertion(
                license="cc-by-4.0",
                commercial_use=True,
                attribution_required=True,
            ),
        ],
        created_at=sample_manifest.created_at,
        previous_manifest_id=sample_manifest.previous_manifest_id,
    )
    assert m2.canonical_bytes() == a


def test_to_json_parses_back(sample_manifest: ContentManifest) -> None:
    blob = sample_manifest.to_json()
    restored = ContentManifest.from_json(blob)
    assert restored.manifest_id == sample_manifest.manifest_id
