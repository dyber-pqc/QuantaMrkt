"""Build a realistic MBOM for Llama-3-8B, sign it, and verify the signature.

Realistic here = realistic *shape*. Content hashes come from hashlib over
dummy blobs so the example is reproducible offline.
"""

from __future__ import annotations

import hashlib

from quantumshield.identity.agent import AgentIdentity

from pqc_mbom import (
    ComponentType,
    LicenseInfo,
    MBOMBuilder,
    MBOMSigner,
    MBOMVerifier,
)


def _h(label: str) -> str:
    return hashlib.sha3_256(label.encode()).hexdigest()


def main() -> None:
    identity = AgentIdentity.create("meta-llama-release-pipeline")

    builder = MBOMBuilder("Llama-3-8B-Instruct", "1.0.0", supplier="Meta")
    builder.set_description(
        "Llama 3 8B instruction-tuned model. Canonical components enumerated "
        "with SHA3-256 content hashes and signed with ML-DSA."
    )

    builder.add_base_architecture(
        "Llama-3-architecture",
        version="3.0",
        content_hash=_h("llama-3-architecture-definition"),
        supplier="Meta",
        license=LicenseInfo(
            spdx_id="llama-3-community",
            name="Llama 3 Community License",
            url="https://llama.meta.com/llama3/license",
            commercial_use=True,
        ),
    )
    builder.add_tokenizer(
        "llama3-tokenizer",
        content_hash=_h("llama3-tiktoken-vocab"),
        supplier="Meta",
        properties={"vocab_size": "128256"},
    )
    builder.add_training_data(
        "pretraining-mix",
        content_hash=_h("pretraining-blob"),
        content_size=15 * 10**12,
        supplier="Meta",
        properties={"source": "15T tokens filtered web + code + books"},
    )
    builder.add_fine_tuning_data(
        "instruct-sft-v1",
        content_hash=_h("sft-dataset"),
        content_size=10 * 10**9,
        supplier="Meta",
    )
    builder.add_rlhf_data(
        "preference-pairs-v1",
        content_hash=_h("preference-pairs"),
        supplier="Meta",
        properties={"pair_count": "1.5M"},
    )
    builder.add_weights(
        "llama3-8b-instruct.safetensors",
        content_hash=_h("llama3-8b-instruct-weights"),
        content_size=16_060_522_240,
        supplier="Meta",
    )
    builder.add_quantization(
        "no-quant-fp16",
        properties={"dtype": "bfloat16", "method": "none"},
    )
    builder.add_evaluation(
        "mmlu-5shot",
        content_hash=_h("mmlu-benchmark-records"),
        external_url="https://github.com/hendrycks/test",
    )
    builder.add_evaluation(
        "human-eval",
        content_hash=_h("human-eval-records"),
    )
    builder.add_component(__import__("pqc_mbom").ModelComponent(
        component_id="safety-guard-1",
        component_type=ComponentType.SAFETY_MODEL,
        name="llama-guard-2",
        content_hash=_h("llama-guard-2-weights"),
    ))

    mbom = builder.build()

    signer = MBOMSigner(identity)
    signer.sign(mbom)

    print("=" * 70)
    print(f"MBOM:           {mbom.mbom_id}")
    print(f"Model:          {mbom.model_name} v{mbom.model_version}")
    print(f"Supplier:       {mbom.supplier}")
    print(f"Created:        {mbom.created_at}")
    print(f"Components:     {len(mbom.components)}")
    print(f"Root hash:      {mbom.components_root_hash}")
    print(f"Signer DID:     {mbom.signer_did}")
    print(f"Algorithm:      {mbom.algorithm}")
    print(f"Signature len:  {len(mbom.signature) // 2} bytes")
    print("=" * 70)
    print("Components:")
    for c in mbom.components:
        size = f"{c.content_size:>15,} B" if c.content_size else " " * 17
        print(f"  - [{c.component_type.value:<22}] {c.name:<35} {size}")

    print("=" * 70)
    result = MBOMVerifier.verify(mbom)
    print(f"Verification: valid={result.valid}")
    print(f"  signature_valid={result.signature_valid}")
    print(f"  root_hash_valid={result.root_hash_valid}")


if __name__ == "__main__":
    main()
