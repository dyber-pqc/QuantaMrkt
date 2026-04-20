# PQC Federated Learning

![PQC Native](https://img.shields.io/badge/PQC-Native-blue)
![ML-DSA-65](https://img.shields.io/badge/ML--DSA--65-FIPS%20204-green)
![License](https://img.shields.io/badge/License-Apache%202.0-orange)
![Version](https://img.shields.io/badge/version-0.1.0-lightgrey)

**Post-quantum secure federated learning.** Every client signs its gradient update with **ML-DSA** (FIPS 204). The aggregator verifies every signature, rejects anything it cannot verify, then emits a **signed aggregation proof** binding the set of included clients to a hash of the aggregated tensors. Pluggable strategies: FedAvg, FedSum, FedMedian, FedTrimmedMean.

## The Problem

Federated learning is sold as a privacy story: training data never leaves the client. But the gradient updates that *do* leave are rarely authenticated end-to-end with quantum-safe crypto. A compromised TLS connection, a malicious coordinator, a "harvest now, decrypt later" adversary sitting on the wire — all of them can substitute, forge, or selectively drop updates to bias the global model. In regulated domains (medical imaging, fraud detection, loan underwriting), this is a 10+ year liability: model provenance must be auditable long after the underlying crypto has fallen.

## The Solution

- **Per-update ML-DSA signature.** Each `ClientUpdate` carries a SHA3-256 content hash and a post-quantum signature over that hash, bound to the client's DID.
- **Signature-gated aggregation.** The `FederatedAggregator` refuses to include any update whose signature does not verify.
- **Optional allow-list.** Provide a `trusted_clients` set to hard-enforce which DIDs may contribute to a round.
- **Signed aggregation proof.** The aggregator emits an `AggregationProof` listing the included client DIDs, update hashes, excluded reasons, and a hash of the final aggregated tensors — signed with ML-DSA by the aggregator's own identity. Auditors can verify the entire round forever.
- **Robust aggregators.** FedMedian and FedTrimmedMean shrug off a bounded number of Byzantine clients (cryptographically valid but value-malicious).

## Installation

```bash
pip install pqc-federated-learning
```

Development:

```bash
pip install -e ".[dev]"
pytest
```

## Quick Start

```python
from quantumshield.identity.agent import AgentIdentity
from pqc_federated_learning import (
    AggregationRound,
    ClientUpdate,
    ClientUpdateMetadata,
    FedAvgAggregator,
    FederatedAggregator,
    GradientTensor,
    UpdateSigner,
)

# 1. Each client has a PQ-AID identity and signs its own update.
client = AgentIdentity.create("hospital-a")

update = ClientUpdate.create(
    metadata=ClientUpdateMetadata(
        client_did=client.did,
        round_id="round-1",
        model_id="pneumonia-detector-v2",
        num_samples=1024,
        epochs=3,
        local_loss=0.18,
    ),
    tensors=[
        GradientTensor(name="conv1.weights", shape=(2, 2), values=(0.1, 0.2, 0.3, 0.4)),
        GradientTensor(name="conv1.bias", shape=(2,), values=(0.01, 0.02)),
    ],
)
signed = UpdateSigner(client).sign(update)

# 2. Coordinator collects N client updates into a round.
round_ = AggregationRound(round_id="round-1", model_id="pneumonia-detector-v2")
round_.add(signed)
# ... add updates from other clients ...

# 3. Aggregator verifies every signature, then aggregates, then signs the result.
aggregator_id = AgentIdentity.create("central-aggregator")
aggregator = FederatedAggregator(
    identity=aggregator_id,
    strategy=FedAvgAggregator(),
    trusted_clients={client.did},  # optional allow-list
    min_updates=1,
)
result = aggregator.aggregate(round_)

# result.aggregated   -> list[GradientTensor] ready to apply to the global model
# result.proof        -> signed AggregationProof with included/excluded DIDs + result hash

assert FederatedAggregator.verify_proof(result.proof)
```

## Architecture

```
   Client A               Client B               Client C
   --------               --------               --------
       |                      |                      |
       | local training       | local training       | local training
       |                      |                      |
       | compute gradient     | compute gradient     | compute gradient
       |                      |                      |
       | sign(update)         | sign(update)         | sign(update)
       |   ML-DSA / SHA3-256  |                      |
       |                      |                      |
       +----------+-----------+----------+-----------+
                  |                      |
                  v                      v
           +----------------------------------+
           |       FederatedAggregator        |
           |                                  |
           |   1. UpdateSigner.verify() per   |
           |      update  (ML-DSA signature,  |
           |      content hash, allow-list)   |
           |                                  |
           |   2. Strategy.aggregate()        |
           |      FedAvg | FedSum |           |
           |      FedMedian | FedTrimmedMean  |
           |                                  |
           |   3. SHA3-256(aggregated)        |
           |                                  |
           |   4. Sign AggregationProof       |
           |      with aggregator's ML-DSA    |
           |      identity                    |
           +----------------+-----------------+
                            |
                            v
              +-------------------------------+
              | AggregationResult             |
              |  - aggregated: [GradientTensor]|
              |  - proof: AggregationProof    |
              |      included_client_dids     |
              |      included_update_hashes   |
              |      excluded_reasons         |
              |      result_hash              |
              |      ML-DSA signature         |
              +-------------------------------+
```

## Threat Model

| Threat | Mitigation |
|---|---|
| **Update forgery** (attacker fabricates an update and claims it came from client A) | Only client A's private key can produce a valid ML-DSA signature over A's DID-bound content hash. |
| **Update tampering in transit** (flip a gradient value) | Recomputed SHA3-256 content hash no longer matches the signed hash; update excluded. |
| **Malicious coordinator** (silently drops honest updates, keeps poisoned ones) | `AggregationProof` is signed by the aggregator and lists every included DID + content hash. Auditors detect missing clients. |
| **Untrusted client joins** (rogue node submits signed updates) | `trusted_clients` allow-list rejects any DID not on the roster. |
| **Byzantine value attack** (valid signature, extreme values) | Use `FedMedianAggregator` or `FedTrimmedMeanAggregator` — they are robust to a bounded fraction of bad clients. |
| **Replay of an old round** | Each update is bound to a `round_id` + `model_id`; `AggregationRound.add()` refuses mismatches. |
| **Harvest-now-decrypt-later** (adversary records traffic today, breaks RSA/ECDSA with a future quantum computer) | ML-DSA is a FIPS 204 post-quantum signature scheme; signatures stay valid against known quantum attacks. |
| **Proof tampering** (auditor is handed a modified proof) | `FederatedAggregator.verify_proof()` recomputes the canonical bytes and checks the aggregator's ML-DSA signature. |

## Why PQC for Federated Learning?

Federated models trained on medical images, financial transactions, or legal corpora have a shelf life measured in **decades**. A forged gradient injected in 2026 still corrupts the downstream model in 2040. Once a classical signature scheme falls to a cryptographically relevant quantum computer, every federated training round ever conducted over that scheme becomes retroactively unverifiable. PQC signatures are the only way to make an FL audit trail that still means something after Q-day.

## API Reference

### `GradientTensor`

Frozen dataclass. A single named tensor.

| Field | Description |
|---|---|
| `name` | Layer name, e.g. `"dense_1.weights"` |
| `shape` | Tuple of ints |
| `values` | Flat tuple of floats (row-major) |

| Method | Description |
|---|---|
| `to_dict()` / `from_dict()` | JSON-safe round-trip |

### `ClientUpdateMetadata`

Frozen dataclass with client DID, round/model ids, `num_samples`, `epochs`, `local_loss`.

### `ClientUpdate`

| Field | Description |
|---|---|
| `metadata` | `ClientUpdateMetadata` |
| `tensors` | `list[GradientTensor]` |
| `created_at` | ISO-8601 timestamp |
| `content_hash` | SHA3-256 over canonical `(metadata, tensors, created_at)` |
| `signer_did`, `public_key`, `algorithm`, `signature`, `signed_at` | Signature envelope |

| Method | Description |
|---|---|
| `ClientUpdate.create(metadata, tensors)` | Build unsigned update with `content_hash` populated |
| `compute_content_hash(metadata, tensors, created_at)` | Static canonical hash |
| `to_dict()` / `from_dict()` | JSON-safe round-trip |

### `UpdateSigner`

| Method | Description |
|---|---|
| `UpdateSigner(identity).sign(update)` | Populate signature envelope (mutates + returns) |
| `UpdateSigner.verify(update)` | Static - returns `UpdateVerificationResult` |

### `AggregationRound`

| Method | Description |
|---|---|
| `AggregationRound(round_id, model_id)` | New empty round |
| `add(update)` | Append update; raises `AggregationError` on round/model mismatch |

### `FederatedAggregator`

| Method | Description |
|---|---|
| `FederatedAggregator(identity, strategy, trusted_clients=None, min_updates=1)` | Construct |
| `aggregate(round_)` | Returns `AggregationResult(aggregated, proof)` |
| `FederatedAggregator.verify_proof(proof)` | Static - verify the aggregator's ML-DSA signature |

### `AggregationProof`

Fields: `round_id`, `model_id`, `aggregator_name`, `included_client_dids`, `included_update_hashes`, `excluded_reasons`, `result_hash`, `num_tensors`, `aggregated_at`, `signer_did`, `algorithm`, `signature`, `public_key`.

Methods: `canonical_bytes()`, `to_dict()`, `to_json()`, `from_dict()`.

### Aggregator strategies

| Strategy | Behavior |
|---|---|
| `FedAvgAggregator()` | Weighted mean by `num_samples`. Default choice. |
| `FedSumAggregator()` | Unweighted element-wise sum. Building block for secure aggregation. |
| `FedMedianAggregator()` | Element-wise median. Robust to a minority of Byzantine clients. |
| `FedTrimmedMeanAggregator(trim_ratio=0.1)` | Drops top/bottom `trim_ratio` fraction before averaging. |

### Exceptions

| Exception | When |
|---|---|
| `FLError` | Base class |
| `InvalidUpdateError` | Structural problems with an update |
| `SignatureVerificationError` | Signature failed to verify |
| `AggregationError` | Round-level error (round/model mismatch) |
| `UntrustedClientError` | DID not in allow-list |
| `ShapeMismatchError` | Tensor names or shapes disagree across updates |
| `InsufficientUpdatesError` | Fewer valid updates than `min_updates` |

## Examples

See the `examples/` directory:

- **`simple_fedavg.py`** - 3 clients, FedAvg, signed aggregation proof.
- **`byzantine_client_rejected.py`** - attacker with a forged signature is excluded.
- **`robust_median.py`** - FedMedian absorbs one malicious client sending extreme values.

Run them:

```bash
python examples/simple_fedavg.py
python examples/byzantine_client_rejected.py
python examples/robust_median.py
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src/ tests/ examples/
```

## Related

Part of the [QuantaMrkt](https://quantamrkt.com) post-quantum tooling registry. See also:

- **QuantumShield** - the PQC toolkit (`AgentIdentity`, `SignatureAlgorithm`, `sign/verify`).
- **PQC RAG Signing** - sign retrieval chunks with ML-DSA.
- **PQC Training Data Transparency** - sign training datasets and commitments.
- **PQC Content Provenance** - sign manifests for generated content.

## License

Apache License 2.0. See [LICENSE](LICENSE).
