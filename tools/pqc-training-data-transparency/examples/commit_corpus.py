"""Commit a training corpus and publish the signed root.

Run:  python examples/commit_corpus.py
"""

from quantumshield import AgentIdentity

from pqc_training_data import (
    CommitmentBuilder,
    CommitmentSigner,
    DataRecord,
)


def main() -> None:
    identity = AgentIdentity.create("model-creator")
    signer = CommitmentSigner(identity)

    # Simulate a small training corpus
    corpus = [
        DataRecord(
            content=b"Patient records: de-identified dataset v3.",
            metadata={"source": "ehr", "id": 1},
        ),
        DataRecord(
            content=b"Medical literature corpus 2024-2026.",
            metadata={"source": "pubmed", "id": 2},
        ),
        DataRecord(
            content=b"Synthetic diagnostic transcripts.",
            metadata={"source": "synthetic", "id": 3},
        ),
        DataRecord(
            content=b"Public domain medical textbooks.",
            metadata={"source": "pd-books", "id": 4},
        ),
        DataRecord(
            content=b"FDA drug approval filings.",
            metadata={"source": "fda", "id": 5},
        ),
    ]

    builder = CommitmentBuilder(
        dataset_name="medical-diagnostics-train-v1",
        dataset_version="1.0.0",
    )
    builder.add_records(corpus)
    builder.licenses = ["cc-by-4.0", "public-domain"]
    builder.tags = ["medical", "diagnostics"]

    commitment = builder.build(
        description="Training data for Medical Diagnostics model v1"
    )
    signed = signer.sign(commitment)

    print("[OK] Commitment created")
    print(f"  commitment_id:  {signed.commitment_id}")
    print(f"  dataset:        {signed.dataset_name} v{signed.dataset_version}")
    print(f"  record_count:   {signed.record_count}")
    print(f"  root:           {signed.root}")
    print(f"  signer_did:     {signed.signer_did}")
    print(f"  algorithm:      {signed.algorithm}")
    print(f"  signature (truncated): {signed.signature[:48]}...")


if __name__ == "__main__":
    main()
