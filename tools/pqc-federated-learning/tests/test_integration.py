"""End-to-end integration tests."""

from __future__ import annotations

from quantumshield.identity.agent import AgentIdentity

from pqc_federated_learning import (
    AggregationRound,
    FedAvgAggregator,
    FedMedianAggregator,
    FederatedAggregator,
)
from tests.conftest import make_signed_update


def test_end_to_end_fedavg_five_clients() -> None:
    aggregator_id = AgentIdentity.create("aggregator")
    client_ids = [AgentIdentity.create(f"client-{i}") for i in range(5)]

    round_ = AggregationRound(round_id="r42", model_id="clf-v3")
    for cid in client_ids:
        update = make_signed_update(
            cid, round_id="r42", model_id="clf-v3", num_samples=100
        )
        round_.add(update)

    aggregator = FederatedAggregator(
        identity=aggregator_id,
        strategy=FedAvgAggregator(),
        trusted_clients={c.did for c in client_ids},
    )
    result = aggregator.aggregate(round_)

    assert len(result.aggregated) == 2
    assert len(result.proof.included_client_dids) == 5
    assert not result.proof.excluded_reasons
    assert FederatedAggregator.verify_proof(result.proof) is True


def test_byzantine_bad_signature_excluded() -> None:
    aggregator_id = AgentIdentity.create("aggregator")
    honest = AgentIdentity.create("honest")
    byz = AgentIdentity.create("byzantine")

    good = make_signed_update(honest)
    bad = make_signed_update(byz)
    # Corrupt signature bytes
    bad.signature = "00" * 64

    round_ = AggregationRound(round_id="round-1", model_id="model-x")
    round_.add(good)
    round_.add(bad)

    aggregator = FederatedAggregator(
        identity=aggregator_id, strategy=FedAvgAggregator()
    )
    result = aggregator.aggregate(round_)
    assert honest.did in result.proof.included_client_dids
    assert byz.did in result.proof.excluded_reasons
    assert FederatedAggregator.verify_proof(result.proof) is True


def test_fedmedian_survives_malicious_client() -> None:
    aggregator_id = AgentIdentity.create("aggregator")
    honest_ids = [AgentIdentity.create(f"honest-{i}") for i in range(4)]
    malicious = AgentIdentity.create("malicious")

    round_ = AggregationRound(round_id="r1", model_id="m1")
    for cid in honest_ids:
        round_.add(make_signed_update(cid, round_id="r1", model_id="m1", values_scale=1.0))
    # Malicious client sends extreme values but signs correctly.
    round_.add(make_signed_update(malicious, round_id="r1", model_id="m1", values_scale=1_000.0))

    aggregator = FederatedAggregator(
        identity=aggregator_id, strategy=FedMedianAggregator()
    )
    result = aggregator.aggregate(round_)
    # Median should still reflect the honest 1.0-scale values.
    w = next(t for t in result.aggregated if t.name == "dense_1.weights")
    expected = (0.1, 0.2, 0.3, 0.4)
    for got, want in zip(w.values, expected):
        assert abs(got - want) < 1e-9
    assert FederatedAggregator.verify_proof(result.proof) is True
