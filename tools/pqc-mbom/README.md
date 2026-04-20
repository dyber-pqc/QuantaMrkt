# PQC AI MBOM

![PQC Native](https://img.shields.io/badge/PQC-Native-blue)
![ML-DSA-65](https://img.shields.io/badge/ML--DSA--65-FIPS%20204-green)
![SPDX](https://img.shields.io/badge/SPDX--2.3-Compatible-purple)
![License](https://img.shields.io/badge/License-Apache%202.0-orange)
![Version](https://img.shields.io/badge/version-0.1.0-lightgrey)

**Bill of Materials for AI models, signed with post-quantum cryptography.** Enumerate every component that went into a model — base architecture, pretraining data, fine-tuning data, RLHF feedback, tokenizer, quantization method, evaluation benchmarks, safety classifiers — hash each one with SHA3-256, commit the whole set to a Merkle-style root, and sign the root with ML-DSA (FIPS 204). The result is a machine-verifiable provenance artifact whose signature will still be valid when a cryptographically-relevant quantum computer arrives in 10-15 years — which matters, because federal AI procurement audits already require 15+ year record retention.

## The Problem

There is no standard, tamper-evident way to declare what an AI model is made of. Model cards are freeform Markdown. Hugging Face repos are a filesystem. SBOM tools like SPDX and CycloneDX were built for software libraries, not datasets, RLHF feedback, or quantization recipes. When a regulator (or your own security team) asks "prove this model wasn't trained on the leaked dataset," the answer is usually an email thread.

Even when providers *do* publish lineage, every signature you see today is RSA or ECDSA — both broken by Shor's algorithm. An AI MBOM signed in 2026 with RSA-2048 will not be verifiable as authentic in 2041. Auditors and procurement officers who keep records for a 15-year retention window will be looking at signatures that a quantum adversary can forge.

## The Solution

`pqc-mbom` is a Python library for producing, signing, and verifying **Model Bill of Materials** documents:

- Each component has a stable id, a type, a SHA3-256 content hash, supplier, author, license, and arbitrary property bag.
- The MBOM commits to `components_root_hash = SHA3-256(sorted component hashes)`.
- The canonical JSON of the MBOM is signed with **ML-DSA** via `quantumshield`.
- SPDX-2.3 interop: `to_spdx_json` / `from_spdx_json` so the output drops into existing SBOM pipelines.
- Diffing: `diff_mboms(old, new)` surfaces added / removed / changed components — the minimum surface area an auditor needs to sign off on a fine-tune.

## Installation

```bash
pip install pqc-mbom
```

Development:

```bash
pip install -e ".[dev]"
```

## Quick Start

```python
from quantumshield.identity.agent import AgentIdentity
from pqc_mbom import MBOMBuilder, MBOMSigner, MBOMVerifier

identity = AgentIdentity.create("llama-release-pipeline")

mbom = (
    MBOMBuilder("Llama-3-8B-Instruct", "1.0.0", supplier="Meta")
    .set_description("Llama 3 8B instruction-tuned.")
    .add_base_architecture("Llama-3", version="3.0", content_hash="a" * 64)
    .add_tokenizer("llama3-tokenizer", content_hash="b" * 64)
    .add_training_data("pretraining-mix", content_hash="c" * 64, content_size=15 * 10**12)
    .add_fine_tuning_data("instruct-sft-v1", content_hash="d" * 64)
    .add_rlhf_data("preference-pairs-v1", content_hash="e" * 64)
    .add_weights("model.safetensors", content_hash="f" * 64, content_size=16_060_522_240)
    .add_quantization("no-quant-fp16")
    .add_evaluation("mmlu-5shot", content_hash="1" * 64)
    .build()
)

MBOMSigner(identity).sign(mbom)                 # fills signer_did / algorithm / signature / public_key
result = MBOMVerifier.verify(mbom)              # VerificationResult(valid=True, ...)
assert result.valid

# Persist
open("llama3-8b.mbom.json", "w").write(mbom.to_json())

# List components by type
from pqc_mbom import ComponentType
for c in mbom.components_by_type(ComponentType.TRAINING_DATA):
    print(c.name, c.content_hash[:16], c.content_size)
```

## Architecture

```
                      +---------------------------+
                      |  MBOMBuilder (fluent API) |
                      +-------------+-------------+
                                    |
                                    v
           +------------------------+------------------------+
           |                        MBOM                     |
           |  mbom_id, schema_version, model_name/version    |
           |  components: [ModelComponent, ...]              |
           |  components_root_hash = SHA3-256(sorted hashes) |
           +-----------+-------------------+-----------------+
                       |                   |
                       v                   v
             +---------+--------+   +------+--------+
             |  MBOMSigner      |   |  to_spdx_json |<----> SPDX-2.3
             |  ML-DSA sign()   |   |  from_spdx    |       interop
             +---------+--------+   +---------------+
                       |
                       v
            +----------+----------+
            |  Signed MBOM JSON   |      +-----------------+
            |  (transport / CDN)  |----->|  MBOMVerifier   |
            +---------------------+      |  ML-DSA verify  |
                                         |  root recompute |
                                         +--------+--------+
                                                  |
                                                  v
                                      VerificationResult
```

## Component Types

| Type                    | Meaning                                                       |
| ----------------------- | ------------------------------------------------------------- |
| `base-architecture`     | Model architecture definition (e.g. Llama-3 decoder layout)   |
| `weights`               | Serialized model weights (safetensors, GGUF, pth)             |
| `training-data`         | Raw pretraining dataset                                       |
| `fine-tuning-data`      | SFT / instruction / domain adaptation data                    |
| `rlhf-data`             | Human preference pairs / feedback data                        |
| `evaluation-benchmark`  | Benchmark corpus used for reported eval numbers               |
| `tokenizer`             | Tokenizer vocab + merges / BPE / SentencePiece artifacts      |
| `quantization-method`   | Quantization recipe (int8 SmoothQuant, GPTQ, AWQ, etc.)       |
| `code`                  | Training / inference code revision                            |
| `config`                | JSON / YAML config files                                      |
| `adapter`               | LoRA / QLoRA adapter weights                                  |
| `safety-model`          | Content filter / classifier (e.g. Llama-Guard)                |
| `other`                 | Anything else worth enumerating                               |

Thirteen types cover the standard model lifecycle. Any arbitrary metadata lives in the per-component `properties: dict[str, str]` bag.

## Cryptography

| Layer             | Algorithm                       | Notes                                                     |
| ----------------- | ------------------------------- | --------------------------------------------------------- |
| Content hashing   | **SHA3-256**                    | Per component and over sorted component hashes            |
| Canonical form    | JSON with `sort_keys=True`      | Deterministic byte-level input to the signer              |
| Signature         | **ML-DSA-65** (FIPS 204)        | Via `quantumshield` — ML-DSA-44 / 87 also supported       |
| Identity          | `did:pqaid:...` (AgentIdentity) | Stable, rotatable signer identity                         |
| Fallback (no oqs) | Ed25519                         | Transitional only — install `quantumshield[pqc]` for real |

The MBOM signature commits to the canonical bytes of the document *including* `components_root_hash`. `MBOMVerifier.verify` both (a) checks the ML-DSA signature and (b) recomputes the root from scratch, so any tamper with a component, the component list, or the stored root is caught.

## Threat Model

| Threat                                                | Caught by                                              |
| ----------------------------------------------------- | ------------------------------------------------------ |
| Forged MBOM (attacker publishes an MBOM they didn't make) | ML-DSA signature fails under attacker's key + trust-policy rejects unknown signer_did |
| Tampered component (flip a byte in a component entry) | Recomputed component hash + recomputed root mismatch  |
| Dataset swap (same component_id, new content_hash)    | Canonical bytes change -> signature invalid; `diff_mboms` reports it as `changed` |
| Component insertion / removal after signing           | `components_root_hash` changes -> signature invalid    |
| Stale signature (published MBOM whose signer rotated) | `signer_did` + `signed_at` let you enforce key-freshness policy |
| Post-quantum forgery (harvest-now / decrypt-later)    | ML-DSA is resistant to Shor's algorithm                |

Trust anchoring (which DIDs are authoritative for a given model supplier) is policy, not cryptography. `pqc-mbom` gives you the cryptographic primitive; your verification layer decides whose signatures to honor.

## Why PQC for AI MBOMs

Federal AI procurement guidance (NIST AI 600-1, OMB M-24-10) pushes retention windows of 10-15 years for AI provenance records. Commercial contracts covering model-derived IP often run longer. Anything signed with RSA or ECDSA today is a ticking clock: once a cryptographically-relevant quantum computer exists, every stored signature can be forged retroactively.

If you're publishing an AI MBOM in 2026 that needs to be verifiable in 2041, you either sign it post-quantum now or you re-sign every artifact every time a new cryptosystem becomes standard. The first option is dramatically cheaper and is what FIPS 204 exists to enable.

## SPDX Compatibility

```python
from pqc_mbom import to_spdx_json, from_spdx_json

blob = to_spdx_json(mbom)                  # SPDX-2.3 JSON document
mbom2 = from_spdx_json(blob)               # roundtrip back
```

Each `ModelComponent` becomes an SPDX `Package`. AI-specific metadata (component_type, MBOM signature, license extras, arbitrary properties) is preserved as structured `annotations` with `pqc-mbom:*` keys. Any SPDX 2.3 consumer — Dependency-Track, OSV, Anchore, the SPDX CLI — can ingest the output as a normal SBOM and will simply ignore the AI extensions. Round-tripping through `from_spdx_json` recovers the full MBOM.

## API Reference

```python
# Components
ModelComponent(component_id, component_type, name, version, content_hash,
               content_size, supplier, author, external_url, license,
               references, properties)
ModelComponent.hash_content(bytes) -> str       # SHA3-256 hex
ModelComponent.canonical_bytes() -> bytes
ModelComponent.hash() -> str                    # canonical SHA3-256
ModelComponent.to_dict() / from_dict()

ComponentType.{BASE_ARCHITECTURE, WEIGHTS, TRAINING_DATA, FINE_TUNING_DATA,
               RLHF_DATA, EVALUATION_BENCHMARK, TOKENIZER, QUANTIZATION_METHOD,
               CODE, CONFIG, ADAPTER, SAFETY_MODEL, OTHER}
LicenseInfo(spdx_id, name, url, commercial_use, attribution_required)
ComponentReference(component_id, relationship)

# MBOM
MBOM.create(model_name, model_version, supplier, description, components)
MBOM.recompute_root() -> str
MBOM.get_component(component_id) -> ModelComponent      # raises MissingComponentError
MBOM.components_by_type(ctype) -> list[ModelComponent]
MBOM.canonical_bytes() -> bytes
MBOM.to_dict() / to_json() / from_dict() / from_json()

MBOMBuilder(model_name, model_version, supplier)
    .set_description(str)
    .add_component(ModelComponent)
    .add_base_architecture(name, version, content_hash, **kwargs)
    .add_weights(name, content_hash, content_size, **kwargs)
    .add_training_data(name, content_hash, content_size, **kwargs)
    .add_fine_tuning_data(name, content_hash, **kwargs)
    .add_rlhf_data(name, content_hash, **kwargs)
    .add_tokenizer(name, content_hash, **kwargs)
    .add_quantization(name, **kwargs)
    .add_evaluation(name, content_hash, **kwargs)
    .build() -> MBOM

# Signing / verification
MBOMSigner(identity).sign(mbom) -> MBOM
MBOMVerifier.verify(mbom) -> VerificationResult
MBOMVerifier.verify_or_raise(mbom) -> VerificationResult  # raises SignatureVerificationError

VerificationResult(signature_valid, root_hash_valid, mbom_id, signer_did,
                   algorithm, error)
VerificationResult.valid            # signature_valid and root_hash_valid

# SPDX
to_spdx_json(mbom, *, indent=2) -> str
from_spdx_json(blob) -> MBOM                    # raises SPDXConversionError

# Diff
diff_mboms(old, new) -> MBOMDiff
MBOMDiff.{added, removed, changed, is_empty}
```

## Exceptions

```
MBOMError
├── InvalidMBOMError
├── SignatureVerificationError
├── ComponentError
│   └── MissingComponentError
└── SPDXConversionError
```

## Examples

| File                                 | Shows                                                      |
| ------------------------------------ | ---------------------------------------------------------- |
| `examples/build_llama_mbom.py`       | End-to-end: build realistic Llama-3-8B MBOM, sign, verify  |
| `examples/detect_dataset_swap.py`    | Diff two versions, catch a training-data swap attempt      |
| `examples/mbom_to_spdx.py`           | Export an MBOM to SPDX-2.3 JSON and round-trip it back     |

Run them with:

```bash
python examples/build_llama_mbom.py
python examples/detect_dataset_swap.py
python examples/mbom_to_spdx.py
```

## License

Apache 2.0 — see [LICENSE](./LICENSE).
