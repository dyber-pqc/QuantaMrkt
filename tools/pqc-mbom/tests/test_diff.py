"""Tests for MBOM diffing."""

from __future__ import annotations

import copy

from pqc_mbom import (
    ComponentType,
    MBOM,
    MBOMBuilder,
    ModelComponent,
    diff_mboms,
)


def _clone_mbom(mbom: MBOM) -> MBOM:
    return MBOM.from_json(mbom.to_json())


def test_added_component_detected(sample_mbom: MBOM) -> None:
    new_mbom = _clone_mbom(sample_mbom)
    new_mbom.components.append(ModelComponent(
        component_id="eval-mmlu",
        component_type=ComponentType.EVALUATION_BENCHMARK,
        name="mmlu",
        content_hash="e" * 64,
    ))
    new_mbom.recompute_root()
    diff = diff_mboms(sample_mbom, new_mbom)
    assert len(diff.added) == 1
    assert diff.added[0].name == "mmlu"
    assert diff.removed == []
    assert diff.changed == []


def test_removed_component_detected(sample_mbom: MBOM) -> None:
    new_mbom = _clone_mbom(sample_mbom)
    new_mbom.components = [c for c in new_mbom.components if c.component_type != ComponentType.TOKENIZER]
    new_mbom.recompute_root()
    diff = diff_mboms(sample_mbom, new_mbom)
    assert len(diff.removed) == 1
    assert diff.removed[0].component_type == ComponentType.TOKENIZER
    assert diff.added == []
    assert diff.changed == []


def test_changed_component_detected(sample_mbom: MBOM) -> None:
    new_mbom = _clone_mbom(sample_mbom)
    # Same component_id but mutated hash - classic dataset-swap scenario.
    target = next(c for c in new_mbom.components if c.component_type == ComponentType.TRAINING_DATA)
    target.content_hash = "ffff" * 16
    new_mbom.recompute_root()
    diff = diff_mboms(sample_mbom, new_mbom)
    assert len(diff.changed) == 1
    old_c, new_c = diff.changed[0]
    assert old_c.component_id == new_c.component_id
    assert old_c.content_hash != new_c.content_hash


def test_no_changes_returns_empty_diff(sample_mbom: MBOM) -> None:
    copy_mbom = _clone_mbom(sample_mbom)
    diff = diff_mboms(sample_mbom, copy_mbom)
    assert diff.added == []
    assert diff.removed == []
    assert diff.changed == []
    assert diff.is_empty


def test_builder_produces_diffable_mboms() -> None:
    # Extra sanity: two independently built MBOMs with same content still
    # produce a meaningful diff (their component_ids differ because of uuid,
    # so they look like full add+remove).
    b1 = MBOMBuilder("M", "1").add_weights("w", content_hash="a" * 64)
    b2 = MBOMBuilder("M", "1").add_weights("w", content_hash="a" * 64)
    d = diff_mboms(b1.build(), b2.build())
    # All ids differ -> everything is add+remove
    assert len(d.added) == 1 and len(d.removed) == 1
    assert not d.is_empty
    _ = copy  # silence unused-import lint
