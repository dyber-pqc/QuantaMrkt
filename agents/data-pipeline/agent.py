"""Data Pipeline -- commits Merkle roots per batch so downstream can verify."""

from __future__ import annotations

import json
from pathlib import Path

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.identity.agent import AgentIdentity

from pqc_training_data import CommitmentBuilder, CommitmentSigner, DataRecord
from pqc_audit_log_fs import InferenceEvent, LogAppender, RotationPolicy


IDENTITY_FILE = Path(__file__).parent / "identity.json"


def load_identity() -> AgentIdentity:
    data = json.loads(IDENTITY_FILE.read_text())
    return AgentIdentity.create(
        data["name"],
        capabilities=data["capabilities"],
        algorithm=SignatureAlgorithm.ML_DSA_87,
    )


def process_batch(agent: AgentIdentity, batch_rows: list[bytes]) -> dict:
    """Ingest a batch, build a signed Merkle commitment, return its dict form."""
    builder = CommitmentBuilder(
        dataset_name="market-ticks-us-equities",
        dataset_version="2026-Q2",
    )
    for row in batch_rows:
        builder.add_record(DataRecord(content=row, metadata={}))
    commitment = builder.build(description="ETL batch 42 - normalized ticks")
    signed = CommitmentSigner(agent).sign(commitment)
    return signed.to_dict()


def main() -> None:
    agent = load_identity()
    print(f"[agent] {agent.did}")

    mock_batch = [f"row-{i}:ticker=ACME,px=12.34".encode() for i in range(128)]
    committed = process_batch(agent, mock_batch)
    print(f"[batch] records={committed['record_count']}")
    print(f"[batch] merkle_root={committed['root'][:24]}...")
    print(f"[batch] signature={committed['signature'][:24]}...")

    log_dir = Path(__file__).parent / "audit-log"
    with LogAppender(
        str(log_dir), agent, rotation=RotationPolicy(max_events_per_segment=100)
    ) as log:
        log.append(
            InferenceEvent.create(
                model_did=agent.did,
                model_version="1.0",
                input_bytes=b"".join(mock_batch),
                output_bytes=committed["root"].encode(),
                decision_type="etl-commit",
                decision_label="batch-accepted",
                actor_did="did:example:pipeline-runner",
                metadata={"commitment_id": committed["commitment_id"]},
            )
        )
    print(f"[audit] segment sealed at {log_dir}")


if __name__ == "__main__":
    main()
