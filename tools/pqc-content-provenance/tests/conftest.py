"""Pytest fixtures."""

from __future__ import annotations

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_content_provenance import (
    AIGeneratedAssertion,
    ContentManifest,
    GenerationContext,
    ManifestSigner,
    ModelAttribution,
    UsageAssertion,
)


@pytest.fixture
def model_identity() -> AgentIdentity:
    return AgentIdentity.create("llama-3-signer")


@pytest.fixture
def signer(model_identity: AgentIdentity) -> ManifestSigner:
    return ManifestSigner(model_identity)


@pytest.fixture
def attacker_identity() -> AgentIdentity:
    return AgentIdentity.create("attacker")


@pytest.fixture
def sample_attribution() -> ModelAttribution:
    return ModelAttribution(
        model_did="did:pqaid:deadbeef",
        model_name="Llama-3-8B-Instruct",
        model_version="1.0",
        registry_url="https://quantamrkt.com/models/meta-llama-Llama-3-8B-Instruct",
        model_manifest_hash="a" * 64,
    )


@pytest.fixture
def sample_context() -> GenerationContext:
    return GenerationContext(
        prompt_hash="b" * 64,
        parameters={"temperature": 0.7, "top_p": 0.9},
        generated_at="2026-04-20T12:00:00Z",
    )


@pytest.fixture
def sample_content() -> bytes:
    return b"This is AI-generated text about post-quantum cryptography."


@pytest.fixture
def sample_manifest(sample_content, sample_attribution, sample_context) -> ContentManifest:
    return ContentManifest.create(
        content=sample_content,
        content_type="text/plain",
        model_attribution=sample_attribution,
        generation_context=sample_context,
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
    )
