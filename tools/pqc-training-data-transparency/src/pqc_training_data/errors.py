"""Exception hierarchy."""


class TrainingDataError(Exception):
    """Base for all training-data-transparency errors."""


class EmptyTreeError(TrainingDataError):
    """Operation requires a non-empty Merkle tree."""


class InclusionProofError(TrainingDataError):
    """Merkle inclusion proof failed to verify."""


class CommitmentVerificationError(TrainingDataError):
    """ML-DSA signature on a commitment failed to verify."""


class IndexOutOfRangeError(TrainingDataError):
    """Leaf index is out of range for the tree."""
