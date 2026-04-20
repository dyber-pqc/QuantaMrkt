"""End-to-end verifier: signature + inclusion proof."""

from __future__ import annotations

from dataclasses import dataclass

from pqc_training_data.commitment import CommitmentSigner, TrainingCommitment
from pqc_training_data.errors import CommitmentVerificationError
from pqc_training_data.merkle import InclusionProof, MerkleTree
from pqc_training_data.record import DataRecord


@dataclass(frozen=True)
class VerificationResult:
    signature_valid: bool
    proof_valid: bool
    leaf_matches_record: bool
    commitment_id: str
    record_leaf_hash: str | None
    claimed_root: str
    error: str | None = None

    @property
    def fully_verified(self) -> bool:
        return self.signature_valid and self.proof_valid and self.leaf_matches_record


class CommitmentVerifier:
    """Verify that (record, proof, commitment) are mutually consistent.

    Use cases:
      - 'Prove this document was in your training set' - caller supplies
        record + proof + commitment; verifier returns True/False.
      - 'Prove this document was NOT in your training set' - impossible in
        general from a Merkle commitment alone (would require a separate
        sorted-tree construction). This verifier handles positive proofs only.
    """

    @staticmethod
    def verify(
        record: DataRecord,
        proof: InclusionProof,
        commitment: TrainingCommitment,
    ) -> VerificationResult:
        sig_valid = CommitmentSigner.verify(commitment)
        proof_valid = MerkleTree.verify_inclusion(proof)
        expected_leaf = record.leaf_hash().hex
        leaf_ok = expected_leaf == proof.leaf_hash
        root_ok = proof.root == commitment.root

        err: str | None = None
        if not sig_valid:
            err = "commitment signature invalid"
        elif not proof_valid:
            err = "inclusion proof failed to verify"
        elif not leaf_ok:
            err = (
                f"record leaf_hash {expected_leaf[:16]}... does not match proof "
                f"{proof.leaf_hash[:16]}..."
            )
        elif not root_ok:
            err = "proof root does not match commitment root"

        return VerificationResult(
            signature_valid=sig_valid,
            proof_valid=proof_valid and root_ok,
            leaf_matches_record=leaf_ok,
            commitment_id=commitment.commitment_id,
            record_leaf_hash=expected_leaf,
            claimed_root=commitment.root,
            error=err,
        )

    @staticmethod
    def verify_or_raise(
        record: DataRecord,
        proof: InclusionProof,
        commitment: TrainingCommitment,
    ) -> None:
        result = CommitmentVerifier.verify(record, proof, commitment)
        if not result.fully_verified:
            raise CommitmentVerificationError(result.error or "verification failed")
