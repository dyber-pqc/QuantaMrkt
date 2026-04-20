"""FederatedAggregator - verify client updates and produce a signed aggregation proof."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.signatures import sign, verify
from quantumshield.identity.agent import AgentIdentity

from pqc_federated_learning.aggregators.base import Aggregator
from pqc_federated_learning.errors import (
    AggregationError,
    InsufficientUpdatesError,
)
from pqc_federated_learning.signer import UpdateSigner
from pqc_federated_learning.update import ClientUpdate, GradientTensor


@dataclass
class AggregationProof:
    """Signed proof of which updates were aggregated and what the result hash is."""

    round_id: str
    model_id: str
    aggregator_name: str
    included_client_dids: list[str]
    included_update_hashes: list[str]  # content_hash of each included update
    excluded_reasons: dict[str, str]  # {client_did: reason} for excluded updates
    result_hash: str  # SHA3-256 of canonical aggregated tensors
    num_tensors: int
    aggregated_at: str
    signer_did: str = ""
    algorithm: str = ""
    signature: str = ""
    public_key: str = ""

    def canonical_bytes(self) -> bytes:
        payload = {
            "round_id": self.round_id,
            "model_id": self.model_id,
            "aggregator_name": self.aggregator_name,
            "included_client_dids": sorted(self.included_client_dids),
            "included_update_hashes": sorted(self.included_update_hashes),
            "excluded_reasons": self.excluded_reasons,
            "result_hash": self.result_hash,
            "num_tensors": self.num_tensors,
            "aggregated_at": self.aggregated_at,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AggregationProof:
        return cls(**data)


@dataclass
class AggregationResult:
    """Outcome of one aggregation: tensors + signed proof."""

    aggregated: list[GradientTensor]
    proof: AggregationProof


@dataclass
class AggregationRound:
    """One federated round: N client updates, configured aggregator."""

    round_id: str
    model_id: str
    updates: list[ClientUpdate] = field(default_factory=list)

    def add(self, update: ClientUpdate) -> None:
        if update.metadata.round_id != self.round_id:
            raise AggregationError(
                f"update round_id {update.metadata.round_id} != round {self.round_id}"
            )
        if update.metadata.model_id != self.model_id:
            raise AggregationError(
                f"update model_id {update.metadata.model_id} != round {self.model_id}"
            )
        self.updates.append(update)


class FederatedAggregator:
    """Verify signed client updates and produce a signed aggregation proof.

    Usage:
        identity = AgentIdentity.create("aggregator")
        aggregator = FederatedAggregator(
            identity=identity,
            strategy=FedAvgAggregator(),
            trusted_clients={"did:pqaid:..."},
        )
        result = aggregator.aggregate(round)
        # result.aggregated: list[GradientTensor]
        # result.proof: AggregationProof (signed with ML-DSA)
    """

    def __init__(
        self,
        identity: AgentIdentity,
        strategy: Aggregator,
        trusted_clients: set[str] | None = None,
        min_updates: int = 1,
    ):
        self.identity = identity
        self.strategy = strategy
        self.trusted_clients = trusted_clients
        self.min_updates = min_updates

    def aggregate(self, round_: AggregationRound) -> AggregationResult:
        accepted: list[ClientUpdate] = []
        excluded: dict[str, str] = {}

        for update in round_.updates:
            # Verify signature
            result = UpdateSigner.verify(update)
            if not result.valid:
                excluded[update.metadata.client_did] = (
                    result.error or "signature invalid"
                )
                continue

            # Allow-list check
            if (
                self.trusted_clients is not None
                and update.metadata.client_did not in self.trusted_clients
            ):
                excluded[update.metadata.client_did] = "client not in trusted set"
                continue

            accepted.append(update)

        if len(accepted) < self.min_updates:
            raise InsufficientUpdatesError(
                f"only {len(accepted)} valid updates, need {self.min_updates}"
            )

        aggregated = self.strategy.aggregate(accepted)

        # Compute result hash: canonical bytes over aggregated tensors
        payload = [t.to_dict() for t in aggregated]
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        result_hash = hashlib.sha3_256(canonical).hexdigest()

        proof = AggregationProof(
            round_id=round_.round_id,
            model_id=round_.model_id,
            aggregator_name=self.strategy.name,
            included_client_dids=[u.metadata.client_did for u in accepted],
            included_update_hashes=[u.content_hash for u in accepted],
            excluded_reasons=excluded,
            result_hash=result_hash,
            num_tensors=len(aggregated),
            aggregated_at=datetime.now(timezone.utc).isoformat(),
        )

        # Sign the proof
        digest = hashlib.sha3_256(proof.canonical_bytes()).digest()
        sig = sign(digest, self.identity.signing_keypair)
        proof.signer_did = self.identity.did
        proof.algorithm = self.identity.signing_keypair.algorithm.value
        proof.signature = sig.hex()
        proof.public_key = self.identity.signing_keypair.public_key.hex()

        return AggregationResult(aggregated=aggregated, proof=proof)

    @staticmethod
    def verify_proof(proof: AggregationProof) -> bool:
        if not proof.signature:
            return False
        try:
            algorithm = SignatureAlgorithm(proof.algorithm)
        except ValueError:
            return False
        digest = hashlib.sha3_256(proof.canonical_bytes()).digest()
        try:
            return verify(
                digest,
                bytes.fromhex(proof.signature),
                bytes.fromhex(proof.public_key),
                algorithm,
            )
        except Exception:
            return False
