"""Device attestation - signed claim that an artifact was stored on a genuine device."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.signatures import sign, verify
from quantumshield.identity.agent import AgentIdentity

from pqc_enclave_sdk.errors import AttestationError


@dataclass
class DeviceAttestation:
    """Signed claim that a specific artifact was stored in a specific device enclave."""

    device_id: str
    device_model: str
    enclave_vendor: str
    artifact_id: str
    artifact_content_hash: str
    issued_at: str
    signer_did: str = ""
    algorithm: str = ""
    signature: str = ""
    public_key: str = ""

    def canonical_bytes(self) -> bytes:
        payload = {
            "device_id": self.device_id,
            "device_model": self.device_model,
            "enclave_vendor": self.enclave_vendor,
            "artifact_id": self.artifact_id,
            "artifact_content_hash": self.artifact_content_hash,
            "issued_at": self.issued_at,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeviceAttestation:
        return cls(**data)


class DeviceAttester:
    """Produce and verify DeviceAttestations using an AgentIdentity bound to the device."""

    def __init__(
        self,
        identity: AgentIdentity,
        device_id: str,
        device_model: str,
        enclave_vendor: str,
    ) -> None:
        self.identity = identity
        self.device_id = device_id
        self.device_model = device_model
        self.enclave_vendor = enclave_vendor

    def attest(self, artifact_id: str, content_hash: str) -> DeviceAttestation:
        att = DeviceAttestation(
            device_id=self.device_id,
            device_model=self.device_model,
            enclave_vendor=self.enclave_vendor,
            artifact_id=artifact_id,
            artifact_content_hash=content_hash,
            issued_at=datetime.now(timezone.utc).isoformat(),
        )
        digest = hashlib.sha3_256(att.canonical_bytes()).digest()
        sig = sign(digest, self.identity.signing_keypair)
        att.signer_did = self.identity.did
        att.algorithm = self.identity.signing_keypair.algorithm.value
        att.signature = sig.hex()
        att.public_key = self.identity.signing_keypair.public_key.hex()
        return att

    @staticmethod
    def verify(attestation: DeviceAttestation) -> bool:
        if not attestation.signature:
            return False
        try:
            algorithm = SignatureAlgorithm(attestation.algorithm)
        except ValueError:
            return False
        digest = hashlib.sha3_256(attestation.canonical_bytes()).digest()
        try:
            return verify(
                digest,
                bytes.fromhex(attestation.signature),
                bytes.fromhex(attestation.public_key),
                algorithm,
            )
        except Exception:
            return False

    @staticmethod
    def verify_or_raise(attestation: DeviceAttestation) -> None:
        if not DeviceAttester.verify(attestation):
            raise AttestationError("device attestation signature invalid")
