# PQC Training Data Transparency

![PQC Native](https://img.shields.io/badge/PQC-Native-blue)
![Merkle SHA3-256](https://img.shields.io/badge/Merkle-SHA3--256-green)
![ML-DSA](https://img.shields.io/badge/ML--DSA-FIPS%20204-green)
![License](https://img.shields.io/badge/License-Apache%202.0-orange)
![Version](https://img.shields.io/badge/version-0.1.0-lightgrey)

**Cryptographic transparency for AI training data.** Build an SHA3-256 Merkle tree over every record in your training set, sign the root with **ML-DSA** (FIPS 204), and publish it. Anyone who holds a single document can later receive an `O(log n)` inclusion proof showing that the record was in the training set — without revealing any of the other records. The audit trail survives the transition to post-quantum cryptography, so commitments made today remain verifiable in 2035 and beyond.

## The Problem

AI copyright litigation, regulatory audits, and red-team requests keep asking the same question: *what exactly was used to train this model?* Model creators today have no cryptographic answer.

- "Prove this document was NOT in your training set" — requires revealing the entire training set (impossible for proprietary or licensed data).
- "Prove your model wasn't trained on PII" — requires deleting, then proving a negative.
- "Which records were used for fine-tune v2 vs v3?" — no binding commitment exists, so claims are unfalsifiable.

And the few audit trails that do exist are typically RSA- or ECDSA-signed. A cryptographically relevant quantum computer breaks those signatures, and the entire audit chain collapses retroactively. Training data provenance has a 15-20 year shelf life; the crypto under it must survive that long.

## The Solution

Commit once, prove selectively:

- Hash every record into a leaf: `SHA3-256(content || canonical(metadata))`.
- Build an SHA3-256 Merkle tree over the leaves.
- Wrap the root in a `TrainingCommitment` (dataset name, version, record count, timestamps, licenses, tags).
- Sign the canonical commitment with **ML-DSA** at model-release time.
- Publish the commitment anywhere — on-chain, in a transparency log, on quantamrkt.com, stapled to the model card.

Later, anyone can ask "was record X in the training set?" The creator returns an inclusion proof (`log₂(n)` sibling hashes). The verifier checks the proof against the signed root. No other record is revealed.

## Installation

```bash
pip install pqc-training-data-transparency
```

Development:

```bash
pip install -e ".[dev]"
```

## Quick Start

### Build and sign a commitment

```python
from quantumshield import AgentIdentity
from pqc_training_data import (
    CommitmentBuilder, CommitmentSigner, DataRecord,
)

identity = AgentIdentity.create("model-creator")
signer = CommitmentSigner(identity)

corpus = [
    DataRecord(content=doc_bytes, metadata={"source": "internal", "id": i})
    for i, doc_bytes in enumerate(your_documents)
]

builder = CommitmentBuilder(dataset_name="model-v1-train", dataset_version="1.0.0")
builder.add_records(corpus)
builder.licenses = ["cc-by-4.0"]
builder.tags = ["production"]

commitment = signer.sign(builder.build(description="Production training set"))

# Publish commitment.to_json() — this is the public audit artifact.
```

### Prove a single record is in the training set

```python
# Auditor holds only one specific record + the public commitment.
proof = builder.tree.inclusion_proof(index=42)
result = CommitmentVerifier.verify(corpus[42], proof, commitment)

assert result.fully_verified
# -> signature_valid=True, proof_valid=True, leaf_matches_record=True
```

### Detect a forged inclusion claim

```python
forged = DataRecord(content=b"never-in-training", metadata={"id": 999})
pretend_proof = builder.tree.inclusion_proof(index=0)  # hijack a real slot

result = CommitmentVerifier.verify(forged, pretend_proof, commitment)
assert not result.fully_verified            # rejected
# result.error: "record leaf_hash ... does not match proof ..."
```

## Architecture

```
  Training Pipeline (creator)                        Audit Path (third party)
  --------------------------                         ------------------------
                                                                |
  records = [doc1, doc2, ..., docN]                             |
         |                                                      |
         | 1. leaf_hash = SHA3-256(                              |
         |       SHA3-256(content) || canonical_json(metadata)) |
         v                                                      |
  [leaf_1, leaf_2, ..., leaf_N]                                 |
         |                                                      |
         | 2. Merkle fold (SHA3-256, 0x00/0x01 domain sep)      |
         v                                                      |
       ROOT                                                     |
         |                                                      |
         | 3. wrap in TrainingCommitment                        |
         |    (id, dataset, version, created_at, ...)           |
         |                                                      |
         | 4. ML-DSA.sign(canonical(commitment))                |
         v                                                      |
  SIGNED COMMITMENT  -->  published (on-chain, log, model card) |
                                                                |
                                                                | 5. request
                                                                |    inclusion
                                                                |    proof for
                                                                |    record R
                                                                v
                          InclusionProof (leaf, siblings, dirs, root)
                                                                |
                                                                | 6. verify:
                                                                |    ML-DSA(commitment) OK?
                                                                |    leaf_hash(R) == proof.leaf?
                                                                |    walk siblings -> root?
                                                                |    proof.root == commitment.root?
                                                                v
                                                         VerificationResult
                                                         (fully_verified T/F)
```

## Threat Model

| Threat | Handled | Notes |
|---|---|---|
| **Forged inclusion claim** (attacker claims doc X is in the set) | Yes | Verifier recomputes `leaf_hash(X)` and compares to the proof; walk to root fails or mismatches. |
| **Tampered commitment signature** (attacker edits dataset_name, record_count, root) | Yes | Canonical bytes change, ML-DSA signature no longer verifies. |
| **Tampered inclusion proof** (attacker flips a sibling hash) | Yes | Root recomputation diverges from signed root. |
| **Quantum forgery in 2035+** (CRQC forges the audit trail retroactively) | Yes | ML-DSA is a FIPS 204 post-quantum signature; not broken by Shor/Grover. |
| **Proving NON-inclusion** (prove a record was *not* in training) | No | Requires a sorted-tree / Verkle construction. Future work. |
| **Revealing private training data** | No (by design) | Commitment contains only the root; proofs reveal `log₂(n)` sibling hashes, never other records. The creator decides what to reveal. |
| **Selective disclosure of metadata fields** | No | A record's metadata is fully inside its leaf. Hashing over `metadata` is all-or-nothing; carve out separate fields into the leaf if you need partial reveals. |
| **Re-publication of old commitment** (attacker re-uses prior root for a new model release) | Partial | `commitment_id` + `dataset_version` + `created_at` are all signed; enforce freshness by policy. |

## API Reference

### `DataRecord`

Frozen dataclass. One training example.

| Field / Method | Description |
|---|---|
| `content: bytes` | Raw record payload (doc text, image bytes, serialized row, ...). |
| `metadata: dict` | Arbitrary metadata — participates in the leaf hash. |
| `canonical_bytes()` | Deterministic `SHA3-256(content) || "|" || canonical_json(metadata)`. |
| `leaf_hash() -> RecordHash` | SHA3-256 of canonical bytes — the Merkle leaf value. |
| `to_dict()` | Safe serialization. **Does not include raw content.** |

### `MerkleTree`

SHA3-256 Merkle tree with RFC6962-style odd-node promotion.

| Method | Description |
|---|---|
| `add(leaf_hash)` / `add_many(leaves)` | Append leaves. |
| `root() -> str` | Hex Merkle root. Raises `EmptyTreeError` for empty trees. |
| `inclusion_proof(index) -> InclusionProof` | `O(log n)` proof for leaf at `index`. |
| `MerkleTree.verify_inclusion(proof) -> bool` | Static verification — independent of tree state. |

### `InclusionProof`

Frozen dataclass carried from prover to verifier.

| Field | Description |
|---|---|
| `leaf_hash` | Hex of the leaf being proven. |
| `index`, `tree_size` | Position and total size at time of proof. |
| `root` | Hex root the prover claims. |
| `siblings`, `directions` | `log₂(n)` sibling hashes + `'L'`/`'R'` flags. |

### `TrainingCommitment`

The signed audit artifact.

| Field | Description |
|---|---|
| `commitment_id` | `urn:pqc-td:<uuid>`. |
| `dataset_name`, `dataset_version`, `description` | Human-readable identification. |
| `record_count`, `root` | Cryptographic binding to the tree. |
| `created_at`, `licenses`, `tags`, `extra` | Provenance metadata — all signed. |
| `signer_did`, `algorithm`, `signature`, `public_key`, `signed_at` | ML-DSA signature block (populated by `CommitmentSigner.sign`). |
| `to_json()` / `from_json()` | Network-safe round-trip. |
| `canonical_bytes()` | Deterministic JSON covered by the signature. |

### `CommitmentBuilder`

Accumulator for records, emits an unsigned `TrainingCommitment`.

| Method | Description |
|---|---|
| `CommitmentBuilder(dataset_name, dataset_version)` | Start a build. |
| `add_record(record)` / `add_records(records)` | Queue records. |
| `add_leaf_hash_hex(hex)` | Direct-add when caller pre-hashed the data. |
| `build(description="") -> TrainingCommitment` | Produce unsigned commitment. |
| `.tree` | Underlying `MerkleTree` — use to generate inclusion proofs later. |

### `CommitmentSigner`

ML-DSA sign + verify.

| Method | Description |
|---|---|
| `CommitmentSigner(identity)` | Wrap a QuantumShield `AgentIdentity`. |
| `sign(commitment) -> TrainingCommitment` | Populate signature fields. |
| `CommitmentSigner.verify(commitment) -> bool` | Static — verify signature against embedded public key. |

### `CommitmentVerifier` + `VerificationResult`

End-to-end check of (record, proof, commitment).

| Method | Description |
|---|---|
| `CommitmentVerifier.verify(record, proof, commitment)` | Returns a `VerificationResult`. |
| `CommitmentVerifier.verify_or_raise(...)` | Raises `CommitmentVerificationError` on any failure. |

`VerificationResult` fields: `signature_valid`, `proof_valid`, `leaf_matches_record`, `commitment_id`, `record_leaf_hash`, `claimed_root`, `error`, and the `fully_verified` property.

### Exceptions

| Exception | When |
|---|---|
| `TrainingDataError` | Base class. |
| `EmptyTreeError` | Tree operation requires at least one leaf. |
| `InclusionProofError` | Malformed or unverifiable proof. |
| `CommitmentVerificationError` | Raised by `verify_or_raise` on failure. |
| `IndexOutOfRangeError` | Leaf index outside `[0, size)`. |

## Why PQC for Training Data

Training data provenance is a 15-to-20-year commitment:

- Regulatory discovery can ask about training data *decades* after the model was released.
- Copyright plaintiffs litigate on timelines that long outlive a model's commercial life.
- Medical, legal, and financial AI systems are audited for the lifetime of the decisions they influenced.

A Merkle commitment signed today with RSA-2048 or ECDSA-P256 becomes forgeable the moment a cryptographically relevant quantum computer exists. An adversary with a CRQC can retroactively forge arbitrary "signed commitments" and "inclusion proofs", collapsing the entire audit trail.

ML-DSA (FIPS 204) is not broken by Shor's algorithm. Commitments minted today remain verifiable through the post-quantum transition.

## Examples

See the `examples/` directory:

- **`commit_corpus.py`** — build a signed commitment over a small training corpus.
- **`prove_inclusion.py`** — produce and verify an `O(log n)` inclusion proof.
- **`detect_false_inclusion_claim.py`** — demonstrate rejection of a forged "my data was in training" claim.

Run them:

```bash
python examples/commit_corpus.py
python examples/prove_inclusion.py
python examples/detect_false_inclusion_claim.py
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src/ tests/ examples/
```

## Related

Part of the [QuantaMrkt](https://quantamrkt.com) post-quantum tooling registry. See also:

- **QuantumShield** — the PQC toolkit (`AgentIdentity`, `SignatureAlgorithm`, `sign/verify`).
- **PQC RAG Signing** — sister tool for signing RAG corpus chunks with ML-DSA.
- **PQC Content Provenance** — signed manifests for content authenticity.
- **PQC MCP Transport** — signed JSON-RPC transport for Model Context Protocol.

## License

Apache License 2.0. See [LICENSE](LICENSE).
