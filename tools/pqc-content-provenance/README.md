# PQC Signed AI Content Provenance

![PQC Native](https://img.shields.io/badge/PQC-Native-blue)
![ML-DSA](https://img.shields.io/badge/ML--DSA-FIPS%20204-green)
![C2PA-Compatible](https://img.shields.io/badge/C2PA-Compatible-purple)
![License](https://img.shields.io/badge/License-Apache%202.0-orange)
![Version](https://img.shields.io/badge/version-0.1.0-lightgrey)

**C2PA for AI outputs, signed with ML-DSA.** Every piece of AI-generated content (text, image, audio) gets a signed provenance manifest that cryptographically proves *which model* produced it, *when*, *from what prompt*, and *under what licensing terms*. Unlike classical C2PA, signatures use **ML-DSA (FIPS 204)** so they survive the quantum transition: audit trails signed today remain verifiable 20+ years from now, even against a future quantum adversary.

## The Problem

Classical C2PA manifests rely on ECDSA / RSA signatures. A sufficiently large quantum computer running Shor's algorithm breaks both. That means every AI-generated article, diagnostic, or trading recommendation you sign today becomes **retroactively forgeable** once CRQCs (cryptographically-relevant quantum computers) arrive. Industries with long audit horizons (healthcare: 10-30 years, finance: 7+ years, legal discovery: indefinite) cannot rely on a classical signature for provenance.

## The Solution

Every AI output is wrapped in a signed **ContentManifest**:

- SHA3-256 content hash binds the manifest to the exact bytes produced.
- **ModelAttribution** names the model, version, and Shield Registry manifest hash.
- **GenerationContext** records prompt hash, parameters, and timestamp.
- **Assertions** — pluggable C2PA-style claims (AI-generated, training summary, usage license).
- **ML-DSA signature** over the canonical digest, by the model's AgentIdentity DID.
- **Provenance chain** links derivations (AI draft -> human edit -> final) so every change has an auditable signer.

At any future date, a verifier recomputes the content hash, re-runs ML-DSA verify on the canonical manifest bytes, and walks the chain. Tampering at any layer is detected.

## Installation

```bash
pip install pqc-content-provenance
```

Development:

```bash
pip install -e ".[dev]"
```

## Quick Start

### Sign an AI output

```python
from quantumshield import AgentIdentity
from pqc_content_provenance import (
    AIGeneratedAssertion,
    ContentManifest,
    GenerationContext,
    ManifestSigner,
    ModelAttribution,
    UsageAssertion,
    embed_manifest,
)

identity = AgentIdentity.create("llama-3-signer")
signer = ManifestSigner(identity)

content = b"AI-generated press release about tool #4."

manifest = ContentManifest.create(
    content=content,
    content_type="text/plain",
    model_attribution=ModelAttribution(
        model_did=identity.did,
        model_name="Llama-3-8B-Instruct",
        model_version="1.0",
        registry_url="https://quantamrkt.com/models/meta-llama-Llama-3-8B-Instruct",
    ),
    generation_context=GenerationContext(
        prompt_hash="ab" * 32,
        parameters={"temperature": 0.7},
        generated_at="2026-04-20T12:00:00Z",
    ),
    assertions=[
        AIGeneratedAssertion(model_name="Llama-3-8B-Instruct", model_version="1.0"),
        UsageAssertion(license="cc-by-4.0", commercial_use=True, attribution_required=True),
    ],
)

signed = signer.sign(manifest)
envelope = embed_manifest(content, signed, mode="sidecar")

# Persist envelope alongside the content -- e.g. output.txt + output.txt.c2pa.json
```

### Verify an AI output

```python
from pqc_content_provenance import extract_manifest, ManifestSigner

manifest, content = extract_manifest(envelope, mode="sidecar")
result = ManifestSigner.verify(manifest, content)

if not result.valid:
    raise RuntimeError(f"provenance check failed: {result.error}")

print(f"valid output from {result.signer_did}")
```

## Architecture

```
  AI Model                Publisher                Consumer / Auditor
  --------                ---------                ------------------
     |                        |                            |
     | 1. generate output     |                            |
     |                        |                            |
     | 2. ContentManifest.create:                          |
     |    - SHA3-256 content hash                          |
     |    - model attribution (from Shield Registry)       |
     |    - generation context (prompt, params, time)      |
     |    - assertions (AI-generated, usage, training)     |
     |                        |                            |
     | 3. ManifestSigner.sign:                             |
     |    - canonical JSON  -> SHA3-256                    |
     |    - ML-DSA signature with AgentIdentity            |
     |                        |                            |
     | 4. embed_manifest  --->| 5. store content + sidecar |
     |    (sidecar or inline) |    in CMS / DB / S3        |
     |                        |                            |
                              | 6. deliver envelope ------>|
                              |                            |
                                                           | 7. extract_manifest
                                                           | 8. ManifestSigner.verify:
                                                           |    - recompute content hash
                                                           |    - ML-DSA verify canonical
                                                           |    - walk ProvenanceChain
                                                           |
                                                           | 9. reject on any mismatch
```

## Threat Model

| Threat | Mitigation |
|---|---|
| **Forged attribution** (claim output came from model X when it didn't) | Manifest ML-DSA signature only verifies against model X's AgentIdentity public key. |
| **Content tampering** (text/image modified after signing) | Recomputed SHA3-256 no longer matches `manifest.content_hash`. |
| **Manifest tampering** (edit claimed model/prompt/license) | ML-DSA signature over canonical bytes breaks as soon as any field changes. |
| **Lost chain of custody** (edits with no signer record) | `ProvenanceChain` enforces `previous_manifest_id` links; each link has its own signer. |
| **Re-used signature across outputs** | Signature is over the canonical bytes of this specific manifest, which includes `content_hash` and `manifest_id`. |
| **Unknown / unregistered assertion** | `ASSERTION_REGISTRY` rejects unknown labels with `UnknownAssertionError`. |
| **Quantum adversary (Shor's algorithm)** | ML-DSA (FIPS 204) is not broken by known quantum attacks. |
| **Long audit horizon** (10-30 year retention) | Post-quantum signatures remain verifiable past classical crypto's expiry. |

## Assertions

Pluggable facts attached to a manifest. Each is a dataclass with a `label` that matches a C2PA-style namespace.

### `AIGeneratedAssertion` — `c2pa.ai_generated`

| Field | Description |
|---|---|
| `model_name`, `model_version`, `model_did` | Which model produced the content |
| `generator_type` | `text` / `image` / `audio` / `video` / `multimodal` |
| `human_edited` | Was it post-edited by a human? |
| `generation_params` | Temperature, top_p, seed, etc. |

### `TrainingAssertion` — `c2pa.training`

| Field | Description |
|---|---|
| `dataset_name`, `dataset_root_hash` | Source training set + Merkle root |
| `fine_tune_dataset`, `fine_tune_root_hash` | Optional fine-tune set |
| `pii_filtered`, `copyright_cleared` | Compliance flags |
| `licenses` | SPDX identifiers, e.g. `["cc-by-4.0", "apache-2.0"]` |

### `UsageAssertion` — `c2pa.usage`

| Field | Description |
|---|---|
| `license` | SPDX identifier or custom string |
| `commercial_use`, `attribution_required` | Rights flags |
| `attribution_text` | Required credit text |
| `jurisdictions` | Country codes where valid |
| `expiry` | ISO-8601 expiry or empty |

Register your own assertion subclass by adding it to `ASSERTION_REGISTRY` with its `label`.

## Chain of Custody

Every derivation (AI draft -> human edit -> legal review) produces a new manifest that references the previous via `previous_manifest_id`. The `ProvenanceChain` verifies:

1. Each manifest's ML-DSA signature.
2. Each manifest's `previous_manifest_id` matches the prior link's `manifest_id`.
3. The whole chain round-trips through `to_dicts()` / `from_dicts()` without loss.

```python
chain = ProvenanceChain()
chain.add(ai_draft_signed)          # signed by model identity
chain.add(human_edit_signed)         # signed by editor identity, prev = ai_draft.manifest_id
chain.add(legal_review_signed)       # signed by legal identity, prev = human_edit.manifest_id

ok, errors = chain.verify_chain()
```

## API Reference

### `ContentManifest`

| Method | Description |
|---|---|
| `ContentManifest.create(content, content_type, attribution, context, assertions=..., previous_manifest_id=...)` | Build an unsigned manifest |
| `ContentManifest.compute_content_hash(bytes)` | Static SHA3-256 helper |
| `canonical_bytes()` | Deterministic bytes used for signing |
| `to_dict()` / `to_json()` / `from_dict()` / `from_json()` | JSON-safe round-trip |

### `ModelAttribution` / `GenerationContext`

Plain dataclasses holding model identity + generation context. Fully JSON-round-trippable.

### `ManifestSigner`

| Method | Description |
|---|---|
| `ManifestSigner(identity)` | Bind a signer to an `AgentIdentity` |
| `sign(manifest)` | In-place sign; returns manifest |
| `sign_and_raise_on_mismatch(manifest, content)` | Defensive: re-check content hash before signing |
| `ManifestSigner.verify(manifest, content=None)` | Static — returns `VerificationResult` |

### `VerificationResult`

Frozen dataclass. Fields: `valid`, `manifest_id`, `signer_did`, `algorithm`, `content_hash_match`, `signature_match`, `error`.

### `ProvenanceChain` / `ProvenanceLink`

| Method | Description |
|---|---|
| `add(manifest)` | Append link; raises `ChainBrokenError` on bad `previous_manifest_id` |
| `verify_chain()` | Returns `(ok, errors)` — verifies every signature and every link |
| `to_dicts()` / `from_dicts(items)` | JSON-safe round-trip |

### `embed_manifest` / `extract_manifest`

| Mode | Description |
|---|---|
| `sidecar` | JSON envelope containing manifest + base64 content. Save to `.c2pa.json`. |
| `text-header` | Inline marker block prepended to text content. |

### Exceptions

| Exception | When |
|---|---|
| `ProvenanceError` | Base class |
| `InvalidManifestError` | Malformed manifest / missing fields / bad JSON |
| `SignatureVerificationError` | Base for signature check failures |
| `ContentHashMismatchError` | Content bytes don't match manifest's claimed hash |
| `ChainBrokenError` | Provenance chain link mismatch |
| `UnknownAssertionError` | Assertion label not in `ASSERTION_REGISTRY` |

## Examples

See the `examples/` directory:

- **`sign_llm_output.py`** — end-to-end: agent signs AI text, embeds into sidecar, extracts, verifies.
- **`detect_tampered_output.py`** — shows that modifying the content bytes after signing is detected.
- **`provenance_chain.py`** — AI draft -> human-edited derivation; each link signed by a different identity.

Run them:

```bash
python examples/sign_llm_output.py
python examples/detect_tampered_output.py
python examples/provenance_chain.py
```

## Why PQC Matters for Provenance

Provenance is fundamentally an **audit-trail** technology: its whole value is being verifiable *later*. "Later" for healthcare is decades; for financial audits, years; for legal discovery, possibly forever. Classical signatures are vulnerable to **Harvest-Now-Decrypt-Later (HNDL)** style retroactive forgery — an adversary who records today's signed outputs can, once quantum-capable, produce indistinguishable fake manifests that appear to have been signed in the past. ML-DSA (FIPS 204) is believed to resist this attack. Signing AI outputs with PQC today is how we guarantee that tomorrow's auditors can still trust yesterday's provenance.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src/ tests/ examples/
```

## Related

Part of the [QuantaMrkt](https://quantamrkt.com) post-quantum tooling registry. See also:

- **QuantumShield** — the PQC toolkit (`AgentIdentity`, `SignatureAlgorithm`, `sign/verify`).
- **PQC RAG Signing** — sister tool for signing RAG pipeline chunks with ML-DSA.
- **PQC MCP Transport** — sister tool for PQC-secured Model Context Protocol transports.

## License

Apache License 2.0. See [LICENSE](LICENSE).
