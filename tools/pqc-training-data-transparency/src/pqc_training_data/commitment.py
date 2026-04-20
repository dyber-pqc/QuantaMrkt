"""TrainingCommitment - a signed Merkle-root commitment to a training dataset."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.signatures import sign, verify
from quantumshield.identity.agent import AgentIdentity

from pqc_training_data.merkle import MerkleTree
from pqc_training_data.record import DataRecord, RecordHash


@dataclass
class TrainingCommitment:
    """Signed commitment to a training dataset's Merkle root.

    Does NOT contain the records themselves - only the root. Records stay
    private; proofs can be issued selectively on demand.
    """

    commitment_id: str
    dataset_name: str
    dataset_version: str
    description: str
    record_count: int
    root: str                                  # hex Merkle root
    created_at: str
    licenses: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    # Filled by CommitmentSigner
    signer_did: str = ""
    algorithm: str = ""
    signature: str = ""                        # hex
    public_key: str = ""                       # hex
    signed_at: str = ""

    def canonical_bytes(self) -> bytes:
        payload = {
            "commitment_id": self.commitment_id,
            "dataset_name": self.dataset_name,
            "dataset_version": self.dataset_version,
            "description": self.description,
            "record_count": self.record_count,
            "root": self.root,
            "created_at": self.created_at,
            "licenses": sorted(self.licenses),
            "tags": sorted(self.tags),
            "extra": self.extra,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TrainingCommitment:
        return cls(
            commitment_id=data["commitment_id"],
            dataset_name=data["dataset_name"],
            dataset_version=data["dataset_version"],
            description=data.get("description", ""),
            record_count=int(data["record_count"]),
            root=data["root"],
            created_at=data.get("created_at", ""),
            licenses=list(data.get("licenses", [])),
            tags=list(data.get("tags", [])),
            extra=dict(data.get("extra", {})),
            signer_did=data.get("signer_did", ""),
            algorithm=data.get("algorithm", ""),
            signature=data.get("signature", ""),
            public_key=data.get("public_key", ""),
            signed_at=data.get("signed_at", ""),
        )

    @classmethod
    def from_json(cls, blob: str) -> TrainingCommitment:
        return cls.from_dict(json.loads(blob))


class CommitmentBuilder:
    """Collect records, compute the Merkle root, produce an unsigned commitment.

    Usage:
        builder = CommitmentBuilder("company-train-v1", "1.0.0")
        for doc in corpus:
            builder.add_record(DataRecord(content=doc.bytes, metadata={...}))
        commitment = builder.build(description="Company training corpus")
    """

    def __init__(self, dataset_name: str, dataset_version: str):
        self.dataset_name = dataset_name
        self.dataset_version = dataset_version
        self.tree = MerkleTree()
        self.licenses: list[str] = []
        self.tags: list[str] = []
        self.extra: dict = {}

    def add_record(self, record: DataRecord) -> None:
        self.tree.add(record.leaf_hash())

    def add_records(self, records: list[DataRecord]) -> None:
        for r in records:
            self.add_record(r)

    def add_leaf_hash_hex(self, hex_hash: str) -> None:
        """Direct-add by leaf hash (when the caller already hashed the data)."""
        self.tree.add(RecordHash(hex=hex_hash))

    def build(self, description: str = "") -> TrainingCommitment:
        return TrainingCommitment(
            commitment_id=f"urn:pqc-td:{uuid.uuid4().hex}",
            dataset_name=self.dataset_name,
            dataset_version=self.dataset_version,
            description=description,
            record_count=self.tree.size,
            root=self.tree.root(),
            created_at=datetime.now(timezone.utc).isoformat(),
            licenses=list(self.licenses),
            tags=list(self.tags),
            extra=dict(self.extra),
        )


class CommitmentSigner:
    """Sign and verify TrainingCommitments with ML-DSA."""

    def __init__(self, identity: AgentIdentity):
        self.identity = identity

    def sign(self, commitment: TrainingCommitment) -> TrainingCommitment:
        canonical = commitment.canonical_bytes()
        digest = hashlib.sha3_256(canonical).digest()
        sig = sign(digest, self.identity.signing_keypair)
        commitment.signer_did = self.identity.did
        commitment.algorithm = self.identity.signing_keypair.algorithm.value
        commitment.signature = sig.hex()
        commitment.public_key = self.identity.signing_keypair.public_key.hex()
        commitment.signed_at = datetime.now(timezone.utc).isoformat()
        return commitment

    @staticmethod
    def verify(commitment: TrainingCommitment) -> bool:
        if not commitment.signature or not commitment.algorithm:
            return False
        try:
            algorithm = SignatureAlgorithm(commitment.algorithm)
        except ValueError:
            return False
        digest = hashlib.sha3_256(commitment.canonical_bytes()).digest()
        try:
            return verify(
                digest,
                bytes.fromhex(commitment.signature),
                bytes.fromhex(commitment.public_key),
                algorithm,
            )
        except Exception:
            return False
