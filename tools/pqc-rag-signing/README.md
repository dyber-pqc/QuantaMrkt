# PQC RAG Signing

![PQC Native](https://img.shields.io/badge/PQC-Native-blue)
![ML-DSA-87](https://img.shields.io/badge/ML--DSA--87-FIPS%20204-green)
![License](https://img.shields.io/badge/License-Apache%202.0-orange)
![Version](https://img.shields.io/badge/version-0.1.0-lightgrey)

**Sigstore for RAG chunks.** Sign every chunk in your Retrieval-Augmented Generation pipeline with **ML-DSA** (FIPS 204) at ingestion time, then cryptographically verify each chunk at retrieval time before it ever reaches your LLM. Prevents vector database poisoning, supply-chain tampering, and silent chunk substitution attacks — even against adversaries with access to your vector DB. Every signature is post-quantum secure.

## The Problem

Enterprise RAG pipelines have no integrity guarantees. Once a chunk lands in a vector database, there is nothing that cryptographically proves it came from the expected ingestion pipeline. An attacker with write access to the vector DB (insider threat, compromised credentials, or a misconfigured index) can inject malicious chunks that look exactly like legitimate ones. The LLM cannot tell the difference, so it grounds its response on poisoned context.

## The Solution

Every chunk is wrapped in a signed envelope at ingestion:

- Canonical SHA3-256 of `(text + metadata + nonce)` — deterministic content hash.
- ML-DSA signature over the content hash, by a known signer DID.
- Per-corpus Merkle-style manifest that commits to the entire set of chunks.
- Allow-list of trusted signers enforced at retrieval.

At retrieval time, any tampering — a flipped bit, a swapped chunk, an injected row — is detected before the LLM sees the content.

## Installation

```bash
pip install pqc-rag-signing
```

Vector-DB extras:

```bash
pip install "pqc-rag-signing[chroma]"
pip install "pqc-rag-signing[pinecone]"
pip install "pqc-rag-signing[qdrant]"
```

Development:

```bash
pip install -e ".[dev]"
```

## Quick Start

### Ingest: sign a corpus

```python
from quantumshield import AgentIdentity
from pqc_rag_signing import Corpus

identity = AgentIdentity.create("my-rag-ingest")

corpus = Corpus(name="company-handbook-v1", identity=identity)
corpus.add_document("handbook.pdf", chunks=[
    "PQC is required for all new systems.",
    "ML-DSA-87 is the preferred signature algorithm.",
])

signed_chunks = corpus.sign_all()
manifest = corpus.build_manifest()

# Store signed_chunks in your vector DB (persist chunk.to_dict() as metadata)
# Persist manifest.to_json() to S3 / disk / git-managed config
```

### Retrieve: verify before the LLM

```python
from pqc_rag_signing import RetrievalVerifier

verifier = RetrievalVerifier(
    trusted_signers={identity.did},   # only these DIDs are accepted
    strict=True,
)

retrieved_chunks = vector_db.query(query_embedding, top_k=5)  # your DB
result = verifier.verify_retrieved(retrieved_chunks)

if not result.all_verified:
    raise RuntimeError(f"{result.failed_count} chunks failed verification!")

# Only cryptographically verified text ever reaches the LLM
safe_context = "\n\n".join(result.verified_texts())
llm_response = your_llm.generate(prompt=query, context=safe_context)
```

## Architecture

```
  Ingest Pipeline                   Vector DB                    Retrieval
  ---------------                   ---------                    ---------
        |                               |                            |
        | 1. chunk text                 |                            |
        |                               |                            |
        | 2. sign each chunk            |                            |
        |    (ML-DSA over SHA3-256)     |                            |
        |                               |                            |
        | 3. build corpus manifest      |                            |
        |    (Merkle root + signature)  |                            |
        |                               |                            |
        | 4. upsert SignedChunks  ----->|                            |
        |                               |                            |
                                        |                            |
                                        | 5. query (embedding) <---- |
                                        |                            |
                                        | 6. retrieve SignedChunks-->|
                                        |                            |
                                                                     | 7. verify_retrieved():
                                                                     |    - recompute content hash
                                                                     |    - verify ML-DSA signature
                                                                     |    - check trusted-signer allow-list
                                                                     |
                                                                     | 8. ONLY verified text
                                                                     |    passed to LLM
```

## Threat Model

| Threat | Mitigation |
|---|---|
| **Vector DB poisoning** (attacker inserts malicious chunks) | Chunks signed by an untrusted DID are rejected at retrieval. |
| **Chunk tampering** (attacker modifies text in place) | Recomputed content hash no longer matches the signed hash. |
| **Metadata tampering** (attacker changes source/index) | Metadata is part of the signed hash input. |
| **Chunk substitution** (swap chunk A for chunk B, both signed) | Manifest verification detects missing or extra chunks in the corpus. |
| **MITM between vector DB and LLM** | All verification is done by the RAG app; no trust in the transport. |
| **Quantum adversary (Shor's algorithm)** | ML-DSA (FIPS 204) is not broken by known quantum attacks. |
| **Replay of old corpus** | Manifests carry `corpus_id` + `created_at`; reject stale manifests by policy. |

## API Reference

### `ChunkMetadata`

Frozen dataclass describing where a chunk came from.

| Field | Description |
|---|---|
| `source` | Source document identifier (filename, URL, etc.) |
| `chunk_index` | Zero-based position within source |
| `total_chunks` | Total chunks in source |
| `start_offset` / `end_offset` | Character offsets in original document |
| `extra` | Arbitrary user-supplied metadata (preserved through signing) |

### `SignedChunk`

| Field | Description |
|---|---|
| `chunk_id` | Unique id (`chunk-<hex>`) |
| `text` | Content used for embedding |
| `metadata` | `ChunkMetadata` |
| `content_hash` | SHA3-256 of canonical `(text, metadata, nonce)` |
| `signer_did`, `public_key`, `algorithm` | Signer identity + algorithm |
| `signature` | Hex ML-DSA signature over `content_hash` |
| `signed_at` | ISO-8601 timestamp |
| `corpus_id` | Optional corpus binding |
| `nonce` | Per-chunk random nonce |

| Method | Description |
|---|---|
| `compute_content_hash(text, metadata, nonce)` | Deterministic canonical hash (static) |
| `to_dict()` / `from_dict()` | JSON-safe round-trip for vector DB metadata |

### `ChunkSigner`

| Method | Description |
|---|---|
| `sign_chunk(text, metadata, chunk_id=None)` | Sign one chunk |
| `sign_chunks(texts, source)` | Batch-sign chunks from one document |
| `verify_chunk(chunk)` | Static — returns `VerificationResult` |
| `verify_chunks(chunks)` | Static — batch verification |

### `VerificationResult`

Frozen dataclass with `valid`, `chunk_id`, `signer_did`, `algorithm`, `error`. Call `.raise_if_invalid()` to convert to an exception.

### `Corpus` + `CorpusManifest`

| Method | Description |
|---|---|
| `Corpus(name, identity, corpus_id=None)` | Start a new corpus build |
| `add_document(source, chunks)` | Queue a document for signing |
| `sign_all()` | Sign all queued chunks |
| `build_manifest(chunks=None)` | Build a signed Merkle-style manifest |
| `verify_manifest(manifest)` | Static — verify the manifest signature and root |
| `verify_chunks_against_manifest(chunks, manifest)` | Static — check every chunk is committed |

### `RetrievalVerifier` + `RetrievalResult`

| Method | Description |
|---|---|
| `RetrievalVerifier(trusted_signers=None, strict=True)` | Build a verifier with optional allow-list |
| `verify_retrieved(chunks)` | Verify batch, return `RetrievalResult` |
| `verify_or_raise(chunks)` | Raise `TamperedChunkError` on any failure |

`RetrievalResult` fields: `total`, `verified`, `failed`, `all_verified`, `verified_count`, `failed_count`, `verified_texts()`.

### `RAGAuditLog` + `RAGAuditEntry`

Append-only in-memory audit trail. `log_sign`, `log_verify`, `log_retrieval`, `entries(...)`, `export_json()`.

### Exceptions

| Exception | When |
|---|---|
| `RAGSigningError` | Base class |
| `ChunkVerificationError` | Any signature check failure |
| `TamperedChunkError` | Content hash does not match |
| `UnsignedChunkError` | Expected signed chunk, got raw text |
| `CorpusIntegrityError` | Manifest mismatch |
| `KeyMismatchError` | Signer DID differs from expected |

## Vector DB Integration

Any vector database that allows arbitrary metadata per record is compatible. Store `SignedChunk.to_dict()` as metadata alongside the embedding, and rebuild the `SignedChunk` at retrieval:

```python
from pqc_rag_signing import SignedChunk

# On ingest:
metadata_blob = signed_chunk.to_dict()
vector_db.upsert(id=signed_chunk.chunk_id,
                 vector=embedding,
                 metadata=metadata_blob)

# On retrieve:
hits = vector_db.query(vector=query_embedding, top_k=5)
signed = [SignedChunk.from_dict(h["metadata"]) for h in hits]
result = verifier.verify_retrieved(signed)
```

The reference `InMemoryAdapter` (in `pqc_rag_signing.adapters`) and the abstract `VectorStoreAdapter` base class show the shape of a real adapter — use them as templates for Chroma, Pinecone, Qdrant, Weaviate, pgvector, and friends.

## Examples

See the `examples/` directory:

- **`simple_ingest.py`** — sign a two-document corpus and build a manifest.
- **`retrieve_and_verify.py`** — full retrieve + verify round-trip with an audit log.
- **`poisoning_attack_demo.py`** — demonstrates detection of a vector-DB poisoning attack.

Run them:

```bash
python examples/simple_ingest.py
python examples/retrieve_and_verify.py
python examples/poisoning_attack_demo.py
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src/ tests/
```

## Related

Part of the [QuantaMrkt](https://quantamrkt.com) post-quantum tooling registry. See also:

- **QuantumShield** — the PQC toolkit (`AgentIdentity`, `SignatureAlgorithm`, `sign/verify`).
- **PQC MCP Transport** — sister tool for signing Model Context Protocol JSON-RPC messages.

## License

Apache License 2.0. See [LICENSE](LICENSE).
