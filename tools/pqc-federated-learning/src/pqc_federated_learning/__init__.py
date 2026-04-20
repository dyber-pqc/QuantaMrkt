"""PQC Federated Learning - ML-DSA-signed gradient updates and verifiable aggregation."""

from pqc_federated_learning.aggregator import (
    AggregationProof,
    AggregationResult,
    AggregationRound,
    FederatedAggregator,
)
from pqc_federated_learning.aggregators.base import Aggregator
from pqc_federated_learning.aggregators.fedavg import FedAvgAggregator
from pqc_federated_learning.aggregators.fedmedian import FedMedianAggregator
from pqc_federated_learning.aggregators.fedsum import FedSumAggregator
from pqc_federated_learning.aggregators.fedtrimmed import FedTrimmedMeanAggregator
from pqc_federated_learning.errors import (
    AggregationError,
    FLError,
    InsufficientUpdatesError,
    InvalidUpdateError,
    ShapeMismatchError,
    SignatureVerificationError,
    UntrustedClientError,
)
from pqc_federated_learning.signer import UpdateSigner, UpdateVerificationResult
from pqc_federated_learning.update import (
    ClientUpdate,
    ClientUpdateMetadata,
    GradientTensor,
)

__version__ = "0.1.0"
__all__ = [
    "ClientUpdate",
    "ClientUpdateMetadata",
    "GradientTensor",
    "UpdateSigner",
    "UpdateVerificationResult",
    "FederatedAggregator",
    "AggregationProof",
    "AggregationRound",
    "AggregationResult",
    "Aggregator",
    "FedAvgAggregator",
    "FedSumAggregator",
    "FedMedianAggregator",
    "FedTrimmedMeanAggregator",
    "FLError",
    "InvalidUpdateError",
    "SignatureVerificationError",
    "AggregationError",
    "UntrustedClientError",
    "ShapeMismatchError",
    "InsufficientUpdatesError",
]
