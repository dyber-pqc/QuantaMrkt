"""Show that a false 'this document was in training' claim is rejected.

Run:  python examples/detect_false_inclusion_claim.py
"""

from quantumshield import AgentIdentity

from pqc_training_data import (
    CommitmentBuilder,
    CommitmentSigner,
    CommitmentVerifier,
    DataRecord,
)


def main() -> None:
    identity = AgentIdentity.create("honest-model-creator")
    signer = CommitmentSigner(identity)

    # Legit training corpus (10 records)
    corpus = [
        DataRecord(content=f"legit-{i}".encode(), metadata={"id": i})
        for i in range(10)
    ]
    builder = CommitmentBuilder("honest-corpus", "1.0.0")
    builder.add_records(corpus)
    commitment = signer.sign(builder.build())

    # A claimant says "this document was in your training set":
    forged = DataRecord(
        content=b"this-never-existed-in-training", metadata={"id": 999}
    )

    # They try to build a proof using one of the real records' slots - the leaf
    # hashes won't match, so verify rejects.
    pretend_proof = builder.tree.inclusion_proof(index=0)  # proof for corpus[0]

    result = CommitmentVerifier.verify(forged, pretend_proof, commitment)
    if result.fully_verified:
        print("[FAIL] False claim was incorrectly accepted!")
    else:
        print("[OK] False inclusion claim was correctly rejected.")
        print(f"     reason: {result.error}")


if __name__ == "__main__":
    main()
