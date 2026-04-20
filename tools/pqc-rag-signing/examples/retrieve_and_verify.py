"""
Retrieve + Verify Example

Shows the retrieval side: load signed chunks from a vector DB,
verify signatures, pass only verified content to the LLM.
"""

import hashlib

from quantumshield import AgentIdentity

from pqc_rag_signing import (
    Corpus,
    InMemoryAdapter,
    RAGAuditLog,
    RetrievalVerifier,
)


def fake_embed(text: str, dim: int = 32) -> list[float]:
    """Deterministic fake embedder for demo purposes."""
    h = hashlib.sha256(text.encode()).digest()
    return [(b - 128) / 128.0 for b in h[:dim]]


def main() -> None:
    # --- Ingest side ---
    identity = AgentIdentity.create("rag-ingest")
    corpus = Corpus(name="demo", identity=identity)
    corpus.add_document(
        "doc1.txt",
        chunks=[
            "Post-quantum cryptography is required by CNSA 2.0.",
            "ML-DSA-87 provides 256-bit post-quantum security.",
            "NIST standardized ML-DSA in FIPS 204.",
        ],
    )
    signed_chunks = corpus.sign_all()

    store = InMemoryAdapter()
    embeddings = [fake_embed(c.text) for c in signed_chunks]
    store.upsert(signed_chunks, embeddings)
    print(f"Stored {store.count()} signed chunks in vector DB")

    # --- Retrieval side ---
    verifier = RetrievalVerifier(
        trusted_signers={identity.did},
        strict=True,
    )
    audit = RAGAuditLog()

    query = "What post-quantum algorithm did NIST standardize?"
    query_embedding = fake_embed(query)
    retrieved = store.query(query_embedding, top_k=3)
    print(f"\nRetrieved {len(retrieved)} candidate chunks for query:")
    print(f'  "{query}"')

    # Verify everything before using it
    result = verifier.verify_retrieved(retrieved)
    audit.log_retrieval(
        query_hash=hashlib.sha3_256(query.encode()).hexdigest(),
        verified_count=result.verified_count,
        failed_count=result.failed_count,
    )

    print("\nVerification result:")
    print(f"  verified:  {result.verified_count}")
    print(f"  failed:    {result.failed_count}")
    print(f"  all valid: {result.all_verified}")

    if result.all_verified:
        print("\n[OK] All chunks verified. Safe to pass to LLM:")
        for text in result.verified_texts():
            print(f"  - {text}")
    else:
        print("\n[WARN] Some chunks failed verification - DO NOT pass to LLM.")
        for chunk, res in result.failed:
            print(f"  - {chunk.chunk_id}: {res.error}")


if __name__ == "__main__":
    main()
