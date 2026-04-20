"""Tests for FederatedAggregator, AggregationRound, and AggregationProof."""

from __future__ import annotations

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_federated_learning import (
    AggregationRound,
    FedAvgAggregator,
    FederatedAggregator,
)
from pqc_federated_learning.errors import (
    AggregationError,
    InsufficientUpdatesError,
)
from tests.conftest import make_signed_update


def test_verified_updates_aggregate(
    aggregator_identity: AgentIdentity,
    client_a_identity: AgentIdentity,
    client_b_identity: AgentIdentity,
) -> None:
    a = make_signed_update(client_a_identity)
    b = make_signed_update(client_b_identity)
    round_ = AggregationRound(round_id="round-1", model_id="model-x")
    round_.add(a)
    round_.add(b)

    agg = FederatedAggregator(
        identity=aggregator_identity, strategy=FedAvgAggregator()
    )
    result = agg.aggregate(round_)
    assert len(result.aggregated) == 2
    assert result.proof.num_tensors == 2
    assert result.proof.signature != ""
    assert set(result.proof.included_client_dids) == {
        client_a_identity.did,
        client_b_identity.did,
    }
    assert not result.proof.excluded_reasons


def test_unsigned_update_excluded(
    aggregator_identity: AgentIdentity,
    client_a_identity: AgentIdentity,
    client_b_identity: AgentIdentity,
) -> None:
    good = make_signed_update(client_a_identity)
    bad = make_signed_update(client_b_identity)
    # Strip signature from bad
    bad.signature = ""

    round_ = AggregationRound(round_id="round-1", model_id="model-x")
    round_.add(good)
    round_.add(bad)

    agg = FederatedAggregator(
        identity=aggregator_identity, strategy=FedAvgAggregator()
    )
    result = agg.aggregate(round_)
    assert client_a_identity.did in result.proof.included_client_dids
    assert client_b_identity.did in result.proof.excluded_reasons


def test_untrusted_client_excluded(
    aggregator_identity: AgentIdentity,
    client_a_identity: AgentIdentity,
    attacker_identity: AgentIdentity,
) -> None:
    good = make_signed_update(client_a_identity)
    attacker = make_signed_update(attacker_identity)

    round_ = AggregationRound(round_id="round-1", model_id="model-x")
    round_.add(good)
    round_.add(attacker)

    agg = FederatedAggregator(
        identity=aggregator_identity,
        strategy=FedAvgAggregator(),
        trusted_clients={client_a_identity.did},
    )
    result = agg.aggregate(round_)
    assert client_a_identity.did in result.proof.included_client_dids
    assert attacker_identity.did in result.proof.excluded_reasons
    assert result.proof.excluded_reasons[attacker_identity.did] == "client not in trusted set"


def test_min_updates_enforced(
    aggregator_identity: AgentIdentity,
    client_a_identity: AgentIdentity,
) -> None:
    a = make_signed_update(client_a_identity)
    round_ = AggregationRound(round_id="round-1", model_id="model-x")
    round_.add(a)

    agg = FederatedAggregator(
        identity=aggregator_identity,
        strategy=FedAvgAggregator(),
        min_updates=2,
    )
    with pytest.raises(InsufficientUpdatesError):
        agg.aggregate(round_)


def test_proof_signed_and_verifiable(
    aggregator_identity: AgentIdentity,
    client_a_identity: AgentIdentity,
    client_b_identity: AgentIdentity,
) -> None:
    a = make_signed_update(client_a_identity)
    b = make_signed_update(client_b_identity)
    round_ = AggregationRound(round_id="round-1", model_id="model-x")
    round_.add(a)
    round_.add(b)

    agg = FederatedAggregator(
        identity=aggregator_identity, strategy=FedAvgAggregator()
    )
    result = agg.aggregate(round_)
    assert FederatedAggregator.verify_proof(result.proof) is True
    assert result.proof.signer_did == aggregator_identity.did


def test_tampered_proof_rejected(
    aggregator_identity: AgentIdentity,
    client_a_identity: AgentIdentity,
    client_b_identity: AgentIdentity,
) -> None:
    a = make_signed_update(client_a_identity)
    b = make_signed_update(client_b_identity)
    round_ = AggregationRound(round_id="round-1", model_id="model-x")
    round_.add(a)
    round_.add(b)

    agg = FederatedAggregator(
        identity=aggregator_identity, strategy=FedAvgAggregator()
    )
    result = agg.aggregate(round_)
    # Flip result hash
    result.proof.result_hash = "0" * 64
    assert FederatedAggregator.verify_proof(result.proof) is False


def test_round_add_validates_round_and_model(
    client_a_identity: AgentIdentity,
) -> None:
    round_ = AggregationRound(round_id="round-1", model_id="model-x")

    wrong_round = make_signed_update(client_a_identity, round_id="round-2", model_id="model-x")
    with pytest.raises(AggregationError):
        round_.add(wrong_round)

    wrong_model = make_signed_update(client_a_identity, round_id="round-1", model_id="model-y")
    with pytest.raises(AggregationError):
        round_.add(wrong_model)


def test_proof_roundtrip_to_dict(
    aggregator_identity: AgentIdentity,
    client_a_identity: AgentIdentity,
    client_b_identity: AgentIdentity,
) -> None:
    a = make_signed_update(client_a_identity)
    b = make_signed_update(client_b_identity)
    round_ = AggregationRound(round_id="round-1", model_id="model-x")
    round_.add(a)
    round_.add(b)

    agg = FederatedAggregator(
        identity=aggregator_identity, strategy=FedAvgAggregator()
    )
    result = agg.aggregate(round_)
    from pqc_federated_learning import AggregationProof

    d = result.proof.to_dict()
    proof2 = AggregationProof.from_dict(d)
    assert FederatedAggregator.verify_proof(proof2) is True
