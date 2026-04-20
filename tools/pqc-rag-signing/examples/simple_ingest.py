"""
Simple RAG Ingest Example

Shows how to sign a small document corpus with ML-DSA so it can be
verified at retrieval time.
"""

from quantumshield import AgentIdentity

from pqc_rag_signing import Corpus


def main() -> None:
    # Create an identity for the ingest pipeline
    identity = AgentIdentity.create("my-company-rag-ingest")
    print(f"Ingest DID: {identity.did}")
    print(f"Algorithm:  {identity.signing_keypair.algorithm.value}")

    # Build a corpus from two documents
    corpus = Corpus(name="company-handbook-v1", identity=identity)
    corpus.add_document(
        "handbook-2026.pdf",
        chunks=[
            "QuantaMrkt employees use ML-DSA-87 for all model signing.",
            "All data in transit uses ML-KEM-1024 key encapsulation.",
            "Classical crypto (RSA, ECDSA) is deprecated for new systems.",
        ],
    )
    corpus.add_document(
        "security-policy.pdf",
        chunks=[
            "All AI agents must have PQ-AID credentials.",
            "Retrieval-augmented systems must use signed chunks.",
        ],
    )

    # Sign every chunk
    signed = corpus.sign_all()
    print(f"\nSigned {len(signed)} chunks")
    for c in signed:
        print(
            f"  {c.chunk_id}  {c.metadata.source}  "
            f"[chunk {c.metadata.chunk_index + 1}/{c.metadata.total_chunks}]"
        )

    # Build a manifest committing to the whole corpus
    manifest = corpus.build_manifest()
    print("\nCorpus manifest:")
    print(f"  corpus_id = {manifest.corpus_id}")
    print(f"  root      = {manifest.root}")
    print(f"  signature = {manifest.signature[:32]}...")
    print("\n[OK] Corpus ready for vector DB ingestion.")


if __name__ == "__main__":
    main()
