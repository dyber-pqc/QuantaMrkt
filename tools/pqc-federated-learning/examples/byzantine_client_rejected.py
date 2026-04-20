"""
Byzantine Client Rejected Example

One honest client + one attacker who forges a signature (wrong key / bad bytes).
The aggregator detects the invalid signature and excludes the attacker
from the aggregation. The signed AggregationProof lists the exclusion
for auditors.
"""

from quantumshield.identity.agent import AgentIdentity

from pqc_federated_learning import (
    AggregationRound,
    ClientUpdate,
    ClientUpdateMetadata,
    FedAvgAggregator,
    FederatedAggregator,
    GradientTensor,
    UpdateSigner,
)


def build_update(
    identity: AgentIdentity,
    round_id: str,
    model_id: str,
    num_samples: int,
) -> ClientUpdate:
    tensors = [
        GradientTensor(name="w", shape=(2,), values=(0.1, 0.2)),
    ]
    meta = ClientUpdateMetadata(
        client_did=identity.did,
        round_id=round_id,
        model_id=model_id,
        num_samples=num_samples,
    )
    update = ClientUpdate.create(meta, tensors)
    return UpdateSigner(identity).sign(update)


def main() -> None:
    round_id = "round-42"
    model_id = "fraud-detector-v1"

    honest = AgentIdentity.create("honest-bank")
    attacker = AgentIdentity.create("evil-bank")

    honest_update = build_update(honest, round_id, model_id, 1000)
    attacker_update = build_update(attacker, round_id, model_id, 5000)

    # Attacker corrupts their own signature bytes (simulates forgery / tampered transit).
    attacker_update.signature = "00" * 64

    aggregator_id = AgentIdentity.create("regulator-aggregator")
    round_ = AggregationRound(round_id=round_id, model_id=model_id)
    round_.add(honest_update)
    round_.add(attacker_update)

    aggregator = FederatedAggregator(
        identity=aggregator_id,
        strategy=FedAvgAggregator(),
        min_updates=1,
    )
    result = aggregator.aggregate(round_)

    print("--- Round summary ---")
    print(f"  total submissions = {len(round_.updates)}")
    print(f"  included          = {len(result.proof.included_client_dids)}")
    print(f"  excluded          = {len(result.proof.excluded_reasons)}")
    print()
    for did, reason in result.proof.excluded_reasons.items():
        print(f"  [EXCLUDED] {did}")
        print(f"             reason: {reason}")

    # The attacker must have been excluded
    assert honest.did in result.proof.included_client_dids
    assert attacker.did in result.proof.excluded_reasons
    assert FederatedAggregator.verify_proof(result.proof)

    print("\n[OK] Attacker excluded. Aggregation proof is valid and PQ-signed.")


if __name__ == "__main__":
    main()
