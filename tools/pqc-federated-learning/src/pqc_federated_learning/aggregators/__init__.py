"""Aggregator strategies."""

from pqc_federated_learning.aggregators.base import Aggregator
from pqc_federated_learning.aggregators.fedavg import FedAvgAggregator
from pqc_federated_learning.aggregators.fedmedian import FedMedianAggregator
from pqc_federated_learning.aggregators.fedsum import FedSumAggregator
from pqc_federated_learning.aggregators.fedtrimmed import FedTrimmedMeanAggregator

__all__ = [
    "Aggregator",
    "FedAvgAggregator",
    "FedSumAggregator",
    "FedMedianAggregator",
    "FedTrimmedMeanAggregator",
]
