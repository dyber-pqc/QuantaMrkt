"""Shared fixtures for pqc-mbom tests."""

from __future__ import annotations

import hashlib

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_mbom import (
    ComponentType,
    LicenseInfo,
    MBOM,
    MBOMBuilder,
    ModelComponent,
)


@pytest.fixture
def creator_identity() -> AgentIdentity:
    return AgentIdentity.create("test-mbom-creator")


@pytest.fixture
def base_arch_component() -> ModelComponent:
    return ModelComponent(
        component_id="base-llama3-0001",
        component_type=ComponentType.BASE_ARCHITECTURE,
        name="Llama-3",
        version="3.0",
        content_hash=hashlib.sha3_256(b"llama-3-architecture").hexdigest(),
        supplier="Meta",
        license=LicenseInfo(spdx_id="llama-3-community", name="Llama 3 Community License"),
    )


@pytest.fixture
def weights_component() -> ModelComponent:
    return ModelComponent(
        component_id="weights-0001",
        component_type=ComponentType.WEIGHTS,
        name="llama3-8b.safetensors",
        content_hash=hashlib.sha3_256(b"fake-weights-blob").hexdigest(),
        content_size=16_000_000_000,
        supplier="Meta",
    )


@pytest.fixture
def training_data_component() -> ModelComponent:
    return ModelComponent(
        component_id="train-cc-2024",
        component_type=ComponentType.TRAINING_DATA,
        name="common-crawl-2024",
        content_hash=hashlib.sha3_256(b"cc-dataset-manifest").hexdigest(),
        content_size=1_000_000_000_000,
        supplier="Common Crawl",
        external_url="https://commoncrawl.org/",
    )


@pytest.fixture
def tokenizer_component() -> ModelComponent:
    return ModelComponent(
        component_id="tok-llama3",
        component_type=ComponentType.TOKENIZER,
        name="llama3-tokenizer",
        content_hash=hashlib.sha3_256(b"tokenizer-vocab").hexdigest(),
    )


@pytest.fixture
def sample_components(
    base_arch_component: ModelComponent,
    weights_component: ModelComponent,
    training_data_component: ModelComponent,
    tokenizer_component: ModelComponent,
) -> list[ModelComponent]:
    return [base_arch_component, weights_component, training_data_component, tokenizer_component]


@pytest.fixture
def sample_mbom(sample_components: list[ModelComponent]) -> MBOM:
    builder = MBOMBuilder("Llama-3-8B-Instruct", "1.0.0", supplier="Meta")
    builder.set_description("Test MBOM for unit tests")
    for c in sample_components:
        builder.add_component(c)
    return builder.build()
