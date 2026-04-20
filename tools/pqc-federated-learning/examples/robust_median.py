"""
Robust Median Aggregation Example

Four honest clients plus one malicious client who signs their update
correctly but ships extreme values designed to bias the global model.
FedMedian absorbs the attack: the per-element median ignores the outlier.
"""

from quantumshield.identity.agent import AgentIdentity

from pqc_federated_learning import (
    AggregationRound,
    ClientUpdate,
    ClientUpdateMetadata,
    FedMedianAggregator,
    FederatedAggregator,
    GradientTensor,
    UpdateSigner,
)


def build_signed_update(
    identity: AgentIdentity,
    round_id: str,
    model_id: str,
    scale: float,
) -> ClientUpdate:
    tensors = [
        GradientTensor(
            name="dense.weights",
            shape=(4,),
            values=tuple(v * scale for v in (0.10, 0.20, 0.30, 0.40)),
        ),
    ]
    meta = ClientUpdateMetadata(
        client_did=identity.did,
        round_id=round_id,
        model_id=model_id,
        num_samples=100,
    )
    update = ClientUpdate.create(meta, tensors)
    return UpdateSigner(identity).sign(update)


def main() -> None:
    round_id = "round-robust-1"
    model_id = "credit-model-v7"

    honest = [AgentIdentity.create(f"bank-{i}") for i in range(4)]
    malicious = AgentIdentity.create("malicious-bank")

    updates = [build_signed_update(h, round_id, model_id, scale=1.0) for h in honest]
    # Malicious client: values are 1000x - designed to bias the mean.
    updates.append(build_signed_update(malicious, round_id, model_id, scale=1_000.0))

    aggregator_id = AgentIdentity.create("regulator-aggregator")
    round_ = AggregationRound(round_id=round_id, model_id=model_id)
    for u in updates:
        round_.add(u)

    aggregator = FederatedAggregator(
        identity=aggregator_id,
        strategy=FedMedianAggregator(),
        trusted_clients={h.did for h in honest} | {malicious.did},
        min_updates=3,
    )
    result = aggregator.aggregate(round_)

    print("--- Robust FedMedian aggregation ---")
    for t in result.aggregated:
        print(f"  {t.name}  shape={t.shape}")
        print(f"    values = {tuple(round(v, 4) for v in t.values)}")

    honest_baseline = (0.10, 0.20, 0.30, 0.40)
    agg_values = next(t.values for t in result.aggregated if t.name == "dense.weights")
    max_drift = max(abs(a - b) for a, b in zip(agg_values, honest_baseline))
    print(f"\n  Max element drift from honest baseline: {max_drift:.6f}")
    print(f"  (Mean aggregation would have drifted by ~{(1000 - 1) * 0.4 / 5:.2f})")

    assert FederatedAggregator.verify_proof(result.proof)
    assert max_drift < 1e-9, "Median should exactly match honest values"

    print("\n[OK] Median survived a 1000x malicious client. Proof PQ-signed.")


if __name__ == "__main__":
    main()
