"""Tests for ModelComponent canonical hashing and serialization."""

from __future__ import annotations

from pqc_mbom import ComponentReference, ComponentType, LicenseInfo, ModelComponent


def test_hash_is_deterministic(weights_component: ModelComponent) -> None:
    first = weights_component.hash()
    second = weights_component.hash()
    assert first == second
    assert len(first) == 64


def test_hash_changes_with_field_change(weights_component: ModelComponent) -> None:
    original = weights_component.hash()
    weights_component.content_hash = "ff" * 32
    assert weights_component.hash() != original


def test_roundtrip_to_dict_from_dict(weights_component: ModelComponent) -> None:
    weights_component.properties = {"framework": "pytorch"}
    weights_component.references = [
        ComponentReference(component_id="base-llama3-0001", relationship="derived-from"),
    ]
    weights_component.license = LicenseInfo(
        spdx_id="apache-2.0",
        name="Apache License 2.0",
        commercial_use=True,
    )
    data = weights_component.to_dict()
    restored = ModelComponent.from_dict(data)
    assert restored.hash() == weights_component.hash()
    assert restored.properties == {"framework": "pytorch"}
    assert restored.license.spdx_id == "apache-2.0"
    assert restored.license.commercial_use is True
    assert restored.references[0].relationship == "derived-from"


def test_license_defaults() -> None:
    lic = LicenseInfo()
    assert lic.spdx_id == ""
    assert lic.commercial_use is False
    assert lic.attribution_required is True


def test_hash_content_sha3_256() -> None:
    digest = ModelComponent.hash_content(b"deterministic-content")
    assert len(digest) == 64
    assert digest == ModelComponent.hash_content(b"deterministic-content")
    assert digest != ModelComponent.hash_content(b"other-content")


def test_component_type_enum_coverage() -> None:
    # Sanity check: every declared component type is usable in canonical bytes.
    for ctype in ComponentType:
        c = ModelComponent(
            component_id=f"id-{ctype.value}",
            component_type=ctype,
            name=f"comp-{ctype.value}",
        )
        # canonical_bytes should not raise, and hash should be 64 hex.
        assert len(c.hash()) == 64
