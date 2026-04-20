"""Prove a specific document was in the training set without revealing the others.

Run:  python examples/prove_inclusion.py
"""

from quantumshield import AgentIdentity

from pqc_training_data import (
    CommitmentBuilder,
    CommitmentSigner,
    CommitmentVerifier,
    DataRecord,
)


def main() -> None:
    identity = AgentIdentity.create("model-creator")
    signer = CommitmentSigner(identity)

    # Creator has 100 private documents. We simulate that.
    corpus = [
        DataRecord(content=f"private-document-{i}".encode(), metadata={"id": i})
        for i in range(100)
    ]
    builder = CommitmentBuilder("private-corpus", "1.0.0")
    builder.add_records(corpus)
    commitment = signer.sign(builder.build())
    print(f"[OK] Committed to {commitment.record_count} records")
    print(f"     root: {commitment.root}")

    # --- Auditor asks: "Was document #42 in the training set?" ---
    # Creator produces an inclusion proof WITHOUT revealing the other 99 records.
    proof = builder.tree.inclusion_proof(index=42)
    print("\n[PROOF] Generated inclusion proof for record #42")
    print(f"        siblings: {len(proof.siblings)} (tree depth)")
    print(f"        size:     {proof.tree_size} leaves")

    # --- Auditor verifies with ONLY: record, proof, commitment ---
    claimed = corpus[42]  # the auditor has only this record
    result = CommitmentVerifier.verify(claimed, proof, commitment)
    print(f"\n[VERIFY] result: fully_verified={result.fully_verified}")
    print(f"         signature_valid={result.signature_valid}")
    print(f"         proof_valid={result.proof_valid}")
    print(f"         leaf_matches={result.leaf_matches_record}")


if __name__ == "__main__":
    main()
