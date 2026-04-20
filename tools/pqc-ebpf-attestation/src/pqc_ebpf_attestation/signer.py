"""BPFSigner produces SignedBPFProgram envelopes; BPFVerifier checks them."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.signatures import sign, verify
from quantumshield.identity.agent import AgentIdentity

from pqc_ebpf_attestation.program import BPFProgram, BPFProgramMetadata, BPFProgramType


@dataclass
class SignedBPFProgram:
    """A BPFProgram + signature envelope.

    The signature is over the program's canonical manifest (metadata + hash),
    not the raw bytecode, so the envelope stays small.
    """

    program: BPFProgram
    signer_did: str
    algorithm: str
    signature: str  # hex
    public_key: str  # hex
    signed_at: str

    def to_dict(self, include_bytecode: bool = True) -> dict[str, Any]:
        return {
            "program": self.program.to_dict(include_bytecode=include_bytecode),
            "signer_did": self.signer_did,
            "algorithm": self.algorithm,
            "signature": self.signature,
            "public_key": self.public_key,
            "signed_at": self.signed_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SignedBPFProgram:
        import base64

        prog_data = data["program"]
        meta_data = prog_data["metadata"]
        metadata = BPFProgramMetadata(
            name=meta_data["name"],
            program_type=BPFProgramType(meta_data["program_type"]),
            license=meta_data.get("license", "GPL"),
            author=meta_data.get("author", ""),
            description=meta_data.get("description", ""),
            version=meta_data.get("version", ""),
            kernel_min=meta_data.get("kernel_min", ""),
            attach_point=meta_data.get("attach_point", ""),
        )
        # Bytecode may or may not be present
        bytecode = b""
        if "bytecode_base64" in prog_data:
            bytecode = base64.b64decode(prog_data["bytecode_base64"])
        program = BPFProgram(
            metadata=metadata,
            bytecode=bytecode,
            bytecode_hash=prog_data.get("bytecode_hash", ""),
            bytecode_size=int(prog_data.get("bytecode_size", 0)),
        )
        return cls(
            program=program,
            signer_did=data["signer_did"],
            algorithm=data["algorithm"],
            signature=data["signature"],
            public_key=data["public_key"],
            signed_at=data.get("signed_at", ""),
        )


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    signature_valid: bool
    hash_consistent: bool  # stored bytecode_hash == hash(actual bytecode)
    signer_did: str | None
    program_name: str
    error: str | None = None


class BPFSigner:
    """Signs BPFPrograms with an AgentIdentity."""

    def __init__(self, identity: AgentIdentity):
        self.identity = identity

    def sign(self, program: BPFProgram) -> SignedBPFProgram:
        canonical = program.canonical_manifest_bytes()
        digest = hashlib.sha3_256(canonical).digest()
        sig = sign(digest, self.identity.signing_keypair)
        return SignedBPFProgram(
            program=program,
            signer_did=self.identity.did,
            algorithm=self.identity.signing_keypair.algorithm.value,
            signature=sig.hex(),
            public_key=self.identity.signing_keypair.public_key.hex(),
            signed_at=datetime.now(timezone.utc).isoformat(),
        )


class BPFVerifier:
    """Independently verify SignedBPFProgram envelopes."""

    @staticmethod
    def verify(signed: SignedBPFProgram) -> VerificationResult:
        # Check bytecode hash matches stored hash when bytecode is present
        hash_ok = True
        if signed.program.bytecode:
            actual = BPFProgram.hash_bytecode(signed.program.bytecode)
            hash_ok = actual == signed.program.bytecode_hash

        # Signature
        try:
            algorithm = SignatureAlgorithm(signed.algorithm)
        except ValueError:
            return VerificationResult(
                valid=False,
                signature_valid=False,
                hash_consistent=hash_ok,
                signer_did=signed.signer_did,
                program_name=signed.program.metadata.name,
                error=f"unknown algorithm {signed.algorithm}",
            )

        canonical = signed.program.canonical_manifest_bytes()
        digest = hashlib.sha3_256(canonical).digest()
        try:
            sig_ok = verify(
                digest,
                bytes.fromhex(signed.signature),
                bytes.fromhex(signed.public_key),
                algorithm,
            )
        except Exception as exc:  # noqa: BLE001 - surface backend failures uniformly
            return VerificationResult(
                valid=False,
                signature_valid=False,
                hash_consistent=hash_ok,
                signer_did=signed.signer_did,
                program_name=signed.program.metadata.name,
                error=f"signature verify failed: {exc}",
            )

        err = None
        valid = sig_ok and hash_ok
        if not sig_ok:
            err = "invalid ML-DSA signature"
        elif not hash_ok:
            err = "bytecode hash does not match stored hash"

        return VerificationResult(
            valid=valid,
            signature_valid=sig_ok,
            hash_consistent=hash_ok,
            signer_did=signed.signer_did,
            program_name=signed.program.metadata.name,
            error=err,
        )
