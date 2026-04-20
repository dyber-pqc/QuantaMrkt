"""Tests for MBOM and MBOMBuilder."""

from __future__ import annotations

import pytest

from pqc_mbom import (
    ComponentType,
    MBOM,
    MBOMBuilder,
    ModelComponent,
)
from pqc_mbom.errors import MissingComponentError


def test_builder_populates_fields() -> None:
    builder = MBOMBuilder("Mixtral-8x22B", "1.0", supplier="Mistral")
    builder.set_description("MoE model")
    builder.add_base_architecture("mixtral", version="1.0", content_hash="a" * 64)
    builder.add_weights("model.safetensors", content_hash="b" * 64, content_size=100)
    mbom = builder.build()
    assert mbom.model_name == "Mixtral-8x22B"
    assert mbom.model_version == "1.0"
    assert mbom.supplier == "Mistral"
    assert mbom.description == "MoE model"
    assert len(mbom.components) == 2
    assert mbom.components[0].component_type == ComponentType.BASE_ARCHITECTURE
    assert mbom.components[1].component_type == ComponentType.WEIGHTS
    assert mbom.mbom_id.startswith("urn:pqc-mbom:")
    assert mbom.components_root_hash  # recomputed on build
    assert mbom.created_at


def test_components_root_hash_is_deterministic(sample_mbom: MBOM) -> None:
    first = sample_mbom.components_root_hash
    second = sample_mbom.recompute_root()
    assert first == second


def test_components_root_hash_changes_with_component_changes(sample_mbom: MBOM) -> None:
    original_root = sample_mbom.components_root_hash
    sample_mbom.components[0].version = "3.1"
    sample_mbom.recompute_root()
    assert sample_mbom.components_root_hash != original_root


def test_get_component_missing_raises(sample_mbom: MBOM) -> None:
    # Existing should return component
    got = sample_mbom.get_component("weights-0001")
    assert got.name == "llama3-8b.safetensors"

    with pytest.raises(MissingComponentError):
        sample_mbom.get_component("not-in-mbom")


def test_components_by_type_filters(sample_mbom: MBOM) -> None:
    weights = sample_mbom.components_by_type(ComponentType.WEIGHTS)
    training = sample_mbom.components_by_type(ComponentType.TRAINING_DATA)
    safety = sample_mbom.components_by_type(ComponentType.SAFETY_MODEL)
    assert len(weights) == 1 and weights[0].name == "llama3-8b.safetensors"
    assert len(training) == 1
    assert safety == []


def test_to_json_from_json_roundtrip(sample_mbom: MBOM) -> None:
    blob = sample_mbom.to_json()
    restored = MBOM.from_json(blob)
    assert restored.mbom_id == sample_mbom.mbom_id
    assert restored.model_name == sample_mbom.model_name
    assert len(restored.components) == len(sample_mbom.components)
    assert restored.components_root_hash == sample_mbom.components_root_hash
    # component-level integrity preserved
    for orig, new in zip(sample_mbom.components, restored.components):
        assert orig.hash() == new.hash()


def test_add_component_accepts_custom_component() -> None:
    builder = MBOMBuilder("Custom", "1")
    custom = ModelComponent(
        component_id="custom-1",
        component_type=ComponentType.ADAPTER,
        name="lora-adapter",
        content_hash="d" * 64,
    )
    builder.add_component(custom)
    mbom = builder.build()
    assert mbom.components[0].component_type == ComponentType.ADAPTER
