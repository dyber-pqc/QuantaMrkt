"""PQC Training Data Transparency - Merkle commitments for AI training datasets."""

from pqc_training_data.commitment import (
    CommitmentBuilder,
    CommitmentSigner,
    TrainingCommitment,
)
from pqc_training_data.errors import (
    CommitmentVerificationError,
    EmptyTreeError,
    InclusionProofError,
    IndexOutOfRangeError,
    TrainingDataError,
)
from pqc_training_data.merkle import InclusionProof, MerkleTree
from pqc_training_data.record import DataRecord, RecordHash
from pqc_training_data.verifier import CommitmentVerifier, VerificationResult

__version__ = "0.1.0"
__all__ = [
    "DataRecord",
    "RecordHash",
    "MerkleTree",
    "InclusionProof",
    "TrainingCommitment",
    "CommitmentBuilder",
    "CommitmentSigner",
    "CommitmentVerifier",
    "VerificationResult",
    "TrainingDataError",
    "EmptyTreeError",
    "InclusionProofError",
    "CommitmentVerificationError",
    "IndexOutOfRangeError",
]
