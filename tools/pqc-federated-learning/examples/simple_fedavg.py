"""
Simple FedAvg Example

Three hospitals train a local model, sign their gradient updates with ML-DSA,
and send them to a central aggregator. The aggregator verifies every signature,
computes a weighted mean (FedAvg), and emits a signed aggregation proof.
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


def build_signed_update(
    identity: AgentIdentity,
    round_id: str,
    model_id: str,
    num_samples: int,
    scale: float,
) -> ClientUpdate:
    tensors = [
        GradientTensor(
            name="conv1.weights",
            shape=(2, 2),
            values=tuple(v * scale for v in (0.1, 0.2, 0.3, 0.4)),
        ),
        GradientTensor(
            name="conv1.bias",
            shape=(2,),
            values=tuple(v * scale for v in (0.01, 0.02)),
        ),
    ]
    meta = ClientUpdateMetadata(
        client_did=identity.did,
        round_id=round_id,
        model_id=model_id,
        num_samples=num_samples,
        epochs=3,
        local_loss=0.42 / scale,
    )
    update = ClientUpdate.create(meta, tensors)
    return UpdateSigner(identity).sign(update)


def main() -> None:
    round_id = "round-1"
    model_id = "pneumonia-detector-v2"

    # Three clients
    hospital_a = AgentIdentity.create("hospital-a")
    hospital_b = AgentIdentity.create("hospital-b")
    hospital_c = AgentIdentity.create("hospital-c")

    print(f"Hospital A DID: {hospital_a.did}")
    print(f"Hospital B DID: {hospital_b.did}")
    print(f"Hospital C DID: {hospital_c.did}")

    u_a = build_signed_update(hospital_a, round_id, model_id, num_samples=1024, scale=1.0)
    u_b = build_signed_update(hospital_b, round_id, model_id, num_samples=512, scale=1.5)
    u_c = build_signed_update(hospital_c, round_id, model_id, num_samples=2048, scale=0.8)

    # Coordinator / aggregator
    aggregator_id = AgentIdentity.create("central-aggregator")
    print(f"\nAggregator DID: {aggregator_id.did}")

    round_ = AggregationRound(round_id=round_id, model_id=model_id)
    round_.add(u_a)
    round_.add(u_b)
    round_.add(u_c)

    aggregator = FederatedAggregator(
        identity=aggregator_id,
        strategy=FedAvgAggregator(),
        trusted_clients={hospital_a.did, hospital_b.did, hospital_c.did},
        min_updates=1,
    )

    result = aggregator.aggregate(round_)

    print("\n--- Aggregated tensors ---")
    for t in result.aggregated:
        preview = ", ".join(f"{v:.5f}" for v in t.values[:4])
        print(f"  {t.name}  shape={t.shape}  values=[{preview}]")

    print("\n--- Aggregation proof ---")
    print(f"  round_id          = {result.proof.round_id}")
    print(f"  model_id          = {result.proof.model_id}")
    print(f"  aggregator_name   = {result.proof.aggregator_name}")
    print(f"  num_tensors       = {result.proof.num_tensors}")
    print(f"  result_hash       = {result.proof.result_hash}")
    print(f"  included clients  = {len(result.proof.included_client_dids)}")
    print(f"  excluded          = {len(result.proof.excluded_reasons)}")
    print(f"  signature[:32]    = {result.proof.signature[:32]}...")

    ok = FederatedAggregator.verify_proof(result.proof)
    print(f"\n[OK] Proof signature verifies: {ok}")


if __name__ == "__main__":
    main()
