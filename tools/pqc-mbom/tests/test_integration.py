"""End-to-end integration tests."""

from __future__ import annotations

import json
from pathlib import Path

from quantumshield.identity.agent import AgentIdentity

from pqc_mbom import (
    ComponentType,
    MBOM,
    MBOMBuilder,
    MBOMSigner,
    MBOMVerifier,
    diff_mboms,
)


def test_full_lifecycle(tmp_path: Path) -> None:
    identity = AgentIdentity.create("release-pipeline")
    builder = MBOMBuilder("Llama-3-8B-Instruct", "1.0.0", supplier="Meta")
    builder.set_description("End-to-end integration model")
    builder.add_base_architecture("Llama-3", version="3.0", content_hash="a" * 64)
    builder.add_training_data("common-crawl-2024", content_hash="b" * 64, content_size=10**12)
    builder.add_fine_tuning_data("instruct-v1", content_hash="c" * 64)
    builder.add_rlhf_data("hh-rlhf", content_hash="d" * 64)
    builder.add_tokenizer("llama3-tokenizer", content_hash="e" * 64)
    builder.add_weights("model.safetensors", content_hash="f" * 64, content_size=16_000_000_000)
    builder.add_evaluation("mmlu", content_hash="1" * 64)
    builder.add_quantization("int8-smoothquant")
    mbom = builder.build()

    assert len(mbom.components) == 8

    # Sign
    MBOMSigner(identity).sign(mbom)

    # Save to disk
    out = tmp_path / "mbom.json"
    out.write_text(mbom.to_json(), encoding="utf-8")

    # Load from disk
    loaded = MBOM.from_json(out.read_text(encoding="utf-8"))
    assert loaded.mbom_id == mbom.mbom_id
    assert loaded.components_root_hash == mbom.components_root_hash

    # Verify
    result = MBOMVerifier.verify_or_raise(loaded)
    assert result.valid
    assert result.signer_did == identity.did

    # Confirm JSON is well-formed
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["schema_version"]
    assert data["signature"]


def test_diff_between_two_versions() -> None:
    identity = AgentIdentity.create("release-pipeline")

    # v1
    v1 = (
        MBOMBuilder("Llama-3-8B-Instruct", "1.0.0", supplier="Meta")
        .add_base_architecture("Llama-3", version="3.0", content_hash="a" * 64)
        .add_weights("model.safetensors", content_hash="w1" * 32, content_size=16_000_000_000)
        .add_training_data("common-crawl-2024", content_hash="t1" * 32)
        .build()
    )
    MBOMSigner(identity).sign(v1)

    # v2 built from v1 - swap training data hash, add an evaluation component,
    # keep other component ids stable to show a change diff.
    v2 = MBOM.from_json(v1.to_json())
    v2.mbom_id = v1.mbom_id.replace("mbom:", "mbom-v2:")
    v2.model_version = "1.0.1"
    for c in v2.components:
        if c.component_type == ComponentType.TRAINING_DATA:
            c.content_hash = "t2" * 32
    v2.components.append(
        type(v2.components[0])(
            component_id="eval-mmlu",
            component_type=ComponentType.EVALUATION_BENCHMARK,
            name="mmlu",
            content_hash="e" * 64,
        )
    )
    v2.recompute_root()
    MBOMSigner(identity).sign(v2)

    diff = diff_mboms(v1, v2)
    assert len(diff.added) == 1
    assert diff.added[0].component_type == ComponentType.EVALUATION_BENCHMARK
    assert len(diff.changed) == 1
    old_td, new_td = diff.changed[0]
    assert old_td.content_hash != new_td.content_hash

    # Both versions still verify individually
    assert MBOMVerifier.verify(v1).valid
    assert MBOMVerifier.verify(v2).valid
