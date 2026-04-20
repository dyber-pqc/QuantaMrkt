"""AttestationClaim and AttestationReport — signed memory-state claims."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from pqc_hypervisor_attestation.region import MemoryRegion, RegionSnapshot


@dataclass
class AttestationClaim:
    """A single claim about a memory region's state."""

    claim_id: str
    region: MemoryRegion
    snapshot: RegionSnapshot
    expected_hash: str = ""              # optional: the hash the claim CLAIMS to be
    workload_id: str = ""                # which AI workload this attests to
    platform: str = ""                   # "amd-sev-snp" | "intel-tdx" | "in-memory" | ...
    nonce: str = ""                      # random, server-supplied for freshness

    @classmethod
    def create(
        cls,
        region: MemoryRegion,
        snapshot: RegionSnapshot,
        expected_hash: str = "",
        workload_id: str = "",
        platform: str = "",
        nonce: str = "",
    ) -> AttestationClaim:
        return cls(
            claim_id=f"urn:pqc-att:{uuid.uuid4().hex}",
            region=region,
            snapshot=snapshot,
            expected_hash=expected_hash,
            workload_id=workload_id,
            platform=platform,
            nonce=nonce,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "region": self.region.to_dict(),
            "snapshot": self.snapshot.to_dict(),
            "expected_hash": self.expected_hash,
            "workload_id": self.workload_id,
            "platform": self.platform,
            "nonce": self.nonce,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttestationClaim:
        reg = data["region"]
        snap = data["snapshot"]
        return cls(
            claim_id=data["claim_id"],
            region=MemoryRegion(**reg),
            snapshot=RegionSnapshot(**snap),
            expected_hash=data.get("expected_hash", ""),
            workload_id=data.get("workload_id", ""),
            platform=data.get("platform", ""),
            nonce=data.get("nonce", ""),
        )


@dataclass
class AttestationReport:
    """Bundle of claims signed with a single ML-DSA signature."""

    report_id: str
    claims: list[AttestationClaim] = field(default_factory=list)
    attester_id: str = ""                # ID of who made the attestation
    platform: str = ""
    issued_at: str = ""
    expires_at: str = ""
    signer_did: str = ""
    algorithm: str = ""
    signature: str = ""                  # hex
    public_key: str = ""                 # hex

    @classmethod
    def create(
        cls,
        claims: list[AttestationClaim],
        attester_id: str = "",
        platform: str = "",
        ttl_seconds: int = 300,
    ) -> AttestationReport:
        now = datetime.now(timezone.utc)
        exp = now + timedelta(seconds=ttl_seconds)
        return cls(
            report_id=f"urn:pqc-attreport:{uuid.uuid4().hex}",
            claims=list(claims),
            attester_id=attester_id,
            platform=platform,
            issued_at=now.isoformat(),
            expires_at=exp.isoformat(),
        )

    def canonical_bytes(self) -> bytes:
        payload = {
            "report_id": self.report_id,
            "claims": [c.to_dict() for c in self.claims],
            "attester_id": self.attester_id,
            "platform": self.platform,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        try:
            exp = datetime.fromisoformat(self.expires_at)
            now = datetime.now(timezone.utc)
            return now > exp
        except ValueError:
            return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "claims": [c.to_dict() for c in self.claims],
            "attester_id": self.attester_id,
            "platform": self.platform,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "signer_did": self.signer_did,
            "algorithm": self.algorithm,
            "signature": self.signature,
            "public_key": self.public_key,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttestationReport:
        return cls(
            report_id=data["report_id"],
            claims=[AttestationClaim.from_dict(c) for c in data.get("claims", [])],
            attester_id=data.get("attester_id", ""),
            platform=data.get("platform", ""),
            issued_at=data.get("issued_at", ""),
            expires_at=data.get("expires_at", ""),
            signer_did=data.get("signer_did", ""),
            algorithm=data.get("algorithm", ""),
            signature=data.get("signature", ""),
            public_key=data.get("public_key", ""),
        )
