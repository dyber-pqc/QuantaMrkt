"""Attester (signs reports) and AttestationVerifier (checks them)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.signatures import sign, verify
from quantumshield.identity.agent import AgentIdentity

from pqc_hypervisor_attestation.claim import AttestationReport
from pqc_hypervisor_attestation.errors import (
    AttestationVerificationError,
    RegionDriftError,
)


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of verifying an AttestationReport."""

    valid: bool
    signature_valid: bool
    not_expired: bool
    drifts: list[str]                    # region_ids whose snapshot != expected
    error: str | None = None


class Attester:
    """Sign AttestationReports with an AgentIdentity."""

    def __init__(self, identity: AgentIdentity):
        self.identity = identity

    def sign(self, report: AttestationReport) -> AttestationReport:
        canonical = report.canonical_bytes()
        digest = hashlib.sha3_256(canonical).digest()
        sig = sign(digest, self.identity.signing_keypair)
        report.signer_did = self.identity.did
        report.algorithm = self.identity.signing_keypair.algorithm.value
        report.signature = sig.hex()
        report.public_key = self.identity.signing_keypair.public_key.hex()
        return report


class AttestationVerifier:
    """Independently verify AttestationReports.

    Checks:
      - ML-DSA signature over canonical bytes
      - Report not expired
      - Each claim's snapshot.content_hash matches its expected_hash (if set)
    """

    @staticmethod
    def verify(
        report: AttestationReport,
        strict: bool = True,
    ) -> VerificationResult:
        # 1. Signature check
        sig_ok = False
        err: str | None = None
        if not report.signature:
            err = "missing signature"
        else:
            try:
                algorithm = SignatureAlgorithm(report.algorithm)
                digest = hashlib.sha3_256(report.canonical_bytes()).digest()
                sig_ok = verify(
                    digest,
                    bytes.fromhex(report.signature),
                    bytes.fromhex(report.public_key),
                    algorithm,
                )
                if not sig_ok:
                    err = "invalid ML-DSA signature"
            except ValueError:
                err = f"unknown algorithm {report.algorithm}"
            except Exception as exc:  # noqa: BLE001 - surface backend failures uniformly
                err = f"signature verify failed: {exc}"

        # 2. Expiry check
        fresh = not report.is_expired()
        if sig_ok and not fresh:
            err = "report expired"

        # 3. Drift check: each claim's snapshot vs expected_hash
        drifts: list[str] = []
        for claim in report.claims:
            if claim.expected_hash and claim.snapshot.content_hash != claim.expected_hash:
                drifts.append(claim.region.region_id)
        if sig_ok and fresh and drifts and strict:
            err = (
                f"memory drift detected in {len(drifts)} region(s): "
                f"{', '.join(drifts)}"
            )

        valid = sig_ok and fresh and (not drifts or not strict)
        return VerificationResult(
            valid=valid,
            signature_valid=sig_ok,
            not_expired=fresh,
            drifts=drifts,
            error=err,
        )

    @staticmethod
    def verify_or_raise(report: AttestationReport, strict: bool = True) -> None:
        result = AttestationVerifier.verify(report, strict=strict)
        if not result.valid:
            if result.drifts:
                raise RegionDriftError(result.error or "drift detected")
            raise AttestationVerificationError(
                result.error or "verification failed"
            )
