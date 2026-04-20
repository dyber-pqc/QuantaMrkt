"""Convert an MBOM to SPDX 2.3 JSON and print the result.

The SPDX output interoperates with existing SBOM tooling (Dependency-Track,
CycloneDX converters, SPDX CLI). AI-specific metadata (component_type,
ML-DSA signature, etc.) survives as structured annotations.
"""

from __future__ import annotations

import hashlib
import json

from quantumshield.identity.agent import AgentIdentity

from pqc_mbom import (
    LicenseInfo,
    MBOMBuilder,
    MBOMSigner,
    from_spdx_json,
    to_spdx_json,
)


def _h(label: str) -> str:
    return hashlib.sha3_256(label.encode()).hexdigest()


def main() -> None:
    identity = AgentIdentity.create("release-pipeline")

    mbom = (
        MBOMBuilder("Mistral-7B-Instruct", "0.3", supplier="Mistral AI")
        .set_description("Demo MBOM exported to SPDX 2.3")
        .add_base_architecture(
            "mistral-7b-architecture",
            version="0.3",
            content_hash=_h("mistral-architecture"),
            license=LicenseInfo(spdx_id="apache-2.0", commercial_use=True),
        )
        .add_tokenizer("mistral-tokenizer", content_hash=_h("mistral-tok"))
        .add_training_data("pretraining-mix", content_hash=_h("train"), content_size=10**12)
        .add_fine_tuning_data("instruct-sft", content_hash=_h("sft"))
        .add_weights("mistral-7b.safetensors", content_hash=_h("weights"), content_size=14 * 10**9)
        .build()
    )
    MBOMSigner(identity).sign(mbom)

    spdx_blob = to_spdx_json(mbom)
    doc = json.loads(spdx_blob)

    print("=" * 70)
    print(f"SPDX document: {doc['name']}")
    print(f"  spdxVersion:   {doc['spdxVersion']}")
    print(f"  dataLicense:   {doc['dataLicense']}")
    print(f"  namespace:     {doc['documentNamespace']}")
    print(f"  packages:      {len(doc['packages'])}")
    print(f"  relationships: {len(doc['relationships'])}")
    print("=" * 70)
    print("Packages:")
    for pkg in doc["packages"]:
        checksum = pkg.get("checksums", [{}])[0].get("checksumValue", "")
        ctype_ann = next(
            (a["comment"] for a in pkg.get("annotations", [])
             if a["comment"].startswith("pqc-mbom:component_type=")),
            "pqc-mbom:component_type=unknown",
        )
        ctype = ctype_ann.split("=", 1)[1]
        print(f"  - {pkg['name']:<40} [{ctype:<22}] sha3-256={checksum[:16]}...")

    print("=" * 70)
    print("Roundtripping SPDX -> MBOM...")
    recovered = from_spdx_json(spdx_blob)
    print(f"  recovered model:      {recovered.model_name} v{recovered.model_version}")
    print(f"  recovered components: {len(recovered.components)}")
    print(f"  root hash matches:    {recovered.components_root_hash == mbom.components_root_hash}")

    print("=" * 70)
    print("First 600 chars of SPDX JSON:")
    print(spdx_blob[:600])
    print("...")


if __name__ == "__main__":
    main()
