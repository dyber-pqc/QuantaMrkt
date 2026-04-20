"""Driver module attestation with ML-DSA.

Every GPU driver / kernel module loaded into the AI inference system gets an
ML-DSA signature over its bytecode hash. At load time, the verifier checks the
signature against an allow-list of signers before permitting the module to load.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.signatures import sign, verify
from quantumshield.identity.agent import AgentIdentity

from pqc_gpu_driver.errors import DriverAttestationError


@dataclass(frozen=True)
class DriverModule:
    """A GPU driver module (e.g. nvidia.ko, amdgpu.ko) binary summary."""

    name: str
    version: str
    module_hash: str                    # hex SHA3-256 of the .ko file
    module_size: int
    target: str = "linux"               # "linux" | "windows" | ...

    def canonical_bytes(self) -> bytes:
        payload = {
            "name": self.name,
            "version": self.version,
            "module_hash": self.module_hash,
            "module_size": self.module_size,
            "target": self.target,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    @staticmethod
    def hash_module_bytes(data: bytes) -> str:
        return hashlib.sha3_256(data).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DriverAttestation:
    """A signed claim about a DriverModule being authorized to load."""

    module: DriverModule
    signer_did: str = ""
    algorithm: str = ""
    signature: str = ""                  # hex
    public_key: str = ""                 # hex
    signed_at: str = ""

    def canonical_bytes(self) -> bytes:
        """Bytes covered by the signature (module only, no signature fields)."""
        return self.module.canonical_bytes()

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module.to_dict(),
            "signer_did": self.signer_did,
            "algorithm": self.algorithm,
            "signature": self.signature,
            "public_key": self.public_key,
            "signed_at": self.signed_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DriverAttestation:
        mod = data["module"]
        return cls(
            module=DriverModule(
                name=mod["name"],
                version=mod["version"],
                module_hash=mod["module_hash"],
                module_size=int(mod["module_size"]),
                target=mod.get("target", "linux"),
            ),
            signer_did=data.get("signer_did", ""),
            algorithm=data.get("algorithm", ""),
            signature=data.get("signature", ""),
            public_key=data.get("public_key", ""),
            signed_at=data.get("signed_at", ""),
        )


class DriverAttester:
    """Signs DriverModule attestations with an AgentIdentity."""

    def __init__(self, identity: AgentIdentity):
        self.identity = identity

    def attest(self, module: DriverModule) -> DriverAttestation:
        att = DriverAttestation(module=module)
        canonical = att.canonical_bytes()
        digest = hashlib.sha3_256(canonical).digest()
        sig = sign(digest, self.identity.signing_keypair)
        att.signer_did = self.identity.did
        att.algorithm = self.identity.signing_keypair.algorithm.value
        att.signature = sig.hex()
        att.public_key = self.identity.signing_keypair.public_key.hex()
        att.signed_at = datetime.now(timezone.utc).isoformat()
        return att


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    module_name: str
    signer_did: str | None
    trusted: bool
    error: str | None = None


class DriverAttestationVerifier:
    """Verify a DriverAttestation against an allow-list of trusted signer DIDs."""

    def __init__(self, trusted_signers: set[str] | None = None):
        self.trusted_signers = trusted_signers

    def verify(
        self,
        attestation: DriverAttestation,
        actual_module_bytes: bytes | None = None,
    ) -> VerificationResult:
        # 1. Module hash must match declared hash when bytes supplied
        if actual_module_bytes is not None:
            actual_hash = DriverModule.hash_module_bytes(actual_module_bytes)
            if actual_hash != attestation.module.module_hash:
                return VerificationResult(
                    valid=False,
                    module_name=attestation.module.name,
                    signer_did=attestation.signer_did,
                    trusted=False,
                    error=(
                        f"module hash mismatch: "
                        f"declared={attestation.module.module_hash[:16]}..., "
                        f"actual={actual_hash[:16]}..."
                    ),
                )

        # 2. Signature must verify
        if not attestation.signature or not attestation.algorithm:
            return VerificationResult(
                valid=False,
                module_name=attestation.module.name,
                signer_did=attestation.signer_did,
                trusted=False,
                error="missing signature fields",
            )
        try:
            algorithm = SignatureAlgorithm(attestation.algorithm)
        except ValueError:
            return VerificationResult(
                valid=False,
                module_name=attestation.module.name,
                signer_did=attestation.signer_did,
                trusted=False,
                error=f"unknown algorithm {attestation.algorithm}",
            )
        digest = hashlib.sha3_256(attestation.canonical_bytes()).digest()
        try:
            sig_ok = verify(
                digest,
                bytes.fromhex(attestation.signature),
                bytes.fromhex(attestation.public_key),
                algorithm,
            )
        except Exception as exc:
            return VerificationResult(
                valid=False,
                module_name=attestation.module.name,
                signer_did=attestation.signer_did,
                trusted=False,
                error=f"signature verify failed: {exc}",
            )
        if not sig_ok:
            return VerificationResult(
                valid=False,
                module_name=attestation.module.name,
                signer_did=attestation.signer_did,
                trusted=False,
                error="invalid ML-DSA signature",
            )

        # 3. Signer must be in the allow-list (if configured)
        trusted = True
        if self.trusted_signers is not None:
            trusted = attestation.signer_did in self.trusted_signers
            if not trusted:
                return VerificationResult(
                    valid=False,
                    module_name=attestation.module.name,
                    signer_did=attestation.signer_did,
                    trusted=False,
                    error=f"signer {attestation.signer_did} not in trusted set",
                )

        return VerificationResult(
            valid=True,
            module_name=attestation.module.name,
            signer_did=attestation.signer_did,
            trusted=trusted,
            error=None,
        )

    def verify_or_raise(
        self,
        attestation: DriverAttestation,
        actual_module_bytes: bytes | None = None,
    ) -> None:
        result = self.verify(attestation, actual_module_bytes)
        if not result.valid:
            raise DriverAttestationError(result.error or "verification failed")
