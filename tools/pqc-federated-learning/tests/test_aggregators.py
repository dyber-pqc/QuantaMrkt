"""Tests for aggregator strategies."""

from __future__ import annotations

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_federated_learning import (
    FedAvgAggregator,
    FedMedianAggregator,
    FedSumAggregator,
    FedTrimmedMeanAggregator,
    GradientTensor,
)
from pqc_federated_learning.errors import (
    InsufficientUpdatesError,
    ShapeMismatchError,
)
from tests.conftest import make_signed_update


def test_fedavg_weighted_mean(
    client_a_identity: AgentIdentity, client_b_identity: AgentIdentity
) -> None:
    a = make_signed_update(client_a_identity, num_samples=100, values_scale=1.0)
    b = make_signed_update(client_b_identity, num_samples=300, values_scale=2.0)
    # tensors: (0.1, 0.2, 0.3, 0.4) with weight 0.25
    #          (0.2, 0.4, 0.6, 0.8) with weight 0.75
    # mean:    (0.175, 0.35, 0.525, 0.7)
    result = FedAvgAggregator().aggregate([a, b])
    assert len(result) == 2
    w = next(t for t in result if t.name == "dense_1.weights")
    expected = (0.175, 0.35, 0.525, 0.7)
    for got, want in zip(w.values, expected):
        assert abs(got - want) < 1e-9


def test_fedavg_equal_weight_when_num_samples_zero(
    client_a_identity: AgentIdentity, client_b_identity: AgentIdentity
) -> None:
    # num_samples=0 is treated as weight 1 (min).
    a = make_signed_update(client_a_identity, num_samples=0, values_scale=1.0)
    b = make_signed_update(client_b_identity, num_samples=0, values_scale=3.0)
    result = FedAvgAggregator().aggregate([a, b])
    w = next(t for t in result if t.name == "dense_1.weights")
    # mean of (0.1,..,0.4) and (0.3,..,1.2) => (0.2, 0.4, 0.6, 0.8)
    expected = (0.2, 0.4, 0.6, 0.8)
    for got, want in zip(w.values, expected):
        assert abs(got - want) < 1e-9


def test_fedsum_plain_sum(
    client_a_identity: AgentIdentity, client_b_identity: AgentIdentity
) -> None:
    a = make_signed_update(client_a_identity, values_scale=1.0)
    b = make_signed_update(client_b_identity, values_scale=2.0)
    result = FedSumAggregator().aggregate([a, b])
    w = next(t for t in result if t.name == "dense_1.weights")
    # (0.1+0.2, 0.2+0.4, 0.3+0.6, 0.4+0.8) = (0.3, 0.6, 0.9, 1.2)
    expected = (0.3, 0.6, 0.9, 1.2)
    for got, want in zip(w.values, expected):
        assert abs(got - want) < 1e-9


def test_fedmedian_robust_to_outlier(
    client_a_identity: AgentIdentity,
    client_b_identity: AgentIdentity,
    client_c_identity: AgentIdentity,
) -> None:
    a = make_signed_update(client_a_identity, values_scale=1.0)
    b = make_signed_update(client_b_identity, values_scale=1.0)
    # Outlier: 100x scale
    c = make_signed_update(client_c_identity, values_scale=100.0)
    result = FedMedianAggregator().aggregate([a, b, c])
    w = next(t for t in result if t.name == "dense_1.weights")
    # Median of (v, v, 100v) with v=(0.1..0.4) -> v
    expected = (0.1, 0.2, 0.3, 0.4)
    for got, want in zip(w.values, expected):
        assert abs(got - want) < 1e-9


def test_fedtrimmedmean_drops_extremes(
    client_a_identity: AgentIdentity,
    client_b_identity: AgentIdentity,
    client_c_identity: AgentIdentity,
) -> None:
    # 5 clients; trim 20% = drop 1 low, 1 high.
    ids = [
        client_a_identity,
        client_b_identity,
        client_c_identity,
        AgentIdentity.create("d"),
        AgentIdentity.create("e"),
    ]
    scales = [1.0, 1.0, 1.0, 1.0, 100.0]  # last is outlier
    updates = [make_signed_update(i, values_scale=s) for i, s in zip(ids, scales)]
    agg = FedTrimmedMeanAggregator(trim_ratio=0.2).aggregate(updates)
    w = next(t for t in agg if t.name == "dense_1.weights")
    # After trim, only three 1.0-scale updates remain -> mean = base values.
    expected = (0.1, 0.2, 0.3, 0.4)
    for got, want in zip(w.values, expected):
        assert abs(got - want) < 1e-9


def test_fedtrimmedmean_rejects_bad_ratio() -> None:
    with pytest.raises(ValueError):
        FedTrimmedMeanAggregator(trim_ratio=0.5)
    with pytest.raises(ValueError):
        FedTrimmedMeanAggregator(trim_ratio=-0.01)


def test_empty_updates_raises() -> None:
    with pytest.raises(InsufficientUpdatesError):
        FedAvgAggregator().aggregate([])
    with pytest.raises(InsufficientUpdatesError):
        FedSumAggregator().aggregate([])
    with pytest.raises(InsufficientUpdatesError):
        FedMedianAggregator().aggregate([])
    with pytest.raises(InsufficientUpdatesError):
        FedTrimmedMeanAggregator().aggregate([])


def test_shape_mismatch_raises(
    client_a_identity: AgentIdentity, client_b_identity: AgentIdentity
) -> None:
    a = make_signed_update(client_a_identity)
    # b uses a different shape for same-named tensor
    bad_tensors = [
        GradientTensor(name="dense_1.weights", shape=(4,), values=(0.1, 0.2, 0.3, 0.4)),
        GradientTensor(name="dense_1.bias", shape=(2,), values=(0.01, 0.02)),
    ]
    b = make_signed_update(client_b_identity, tensors=bad_tensors)
    with pytest.raises(ShapeMismatchError):
        FedAvgAggregator().aggregate([a, b])
    with pytest.raises(ShapeMismatchError):
        FedSumAggregator().aggregate([a, b])


def test_tensor_name_mismatch_raises(
    client_a_identity: AgentIdentity, client_b_identity: AgentIdentity
) -> None:
    a = make_signed_update(client_a_identity)
    bad_tensors = [
        GradientTensor(name="other.weights", shape=(2, 2), values=(0.1, 0.2, 0.3, 0.4)),
        GradientTensor(name="other.bias", shape=(2,), values=(0.01, 0.02)),
    ]
    b = make_signed_update(client_b_identity, tensors=bad_tensors)
    with pytest.raises(ShapeMismatchError):
        FedAvgAggregator().aggregate([a, b])
    with pytest.raises(ShapeMismatchError):
        FedMedianAggregator().aggregate([a, b])
    with pytest.raises(ShapeMismatchError):
        FedTrimmedMeanAggregator().aggregate([a, b])
