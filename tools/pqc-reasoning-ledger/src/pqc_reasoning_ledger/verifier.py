"""TraceVerifier - independently check a SealedTrace."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.signatures import verify

from pqc_reasoning_ledger.errors import SignatureVerificationError
from pqc_reasoning_ledger.merkle import compute_merkle_root
from pqc_reasoning_ledger.trace import SealedTrace


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    signature_valid: bool
    chain_intact: bool
    merkle_root_valid: bool
    step_count: int
    error: str | None = None

    @property
    def fully_verified(self) -> bool:
        return self.signature_valid and self.chain_intact and self.merkle_root_valid


class TraceVerifier:
    """Independently verify a SealedTrace: chain + merkle + signature."""

    @staticmethod
    def verify(sealed: SealedTrace) -> VerificationResult:
        # 1. Verify chain integrity: each step's previous_step_hash references prior step_hash
        chain_ok = True
        prev = "0" * 64
        for s in sealed.steps:
            expected_hash = s.compute_step_hash()
            if s.step_hash != expected_hash:
                chain_ok = False
                break
            if s.previous_step_hash != prev:
                chain_ok = False
                break
            prev = s.step_hash

        if sealed.steps and prev != sealed.final_chain_hash:
            chain_ok = False

        # 2. Verify Merkle root
        recomputed = (
            compute_merkle_root([s.step_hash for s in sealed.steps])
            if sealed.steps
            else ""
        )
        merkle_ok = recomputed == sealed.merkle_root

        # 3. Verify signature
        sig_ok = False
        err: str | None = None
        if not sealed.signature or not sealed.algorithm:
            err = "missing signature"
        else:
            try:
                algorithm = SignatureAlgorithm(sealed.algorithm)
                digest = hashlib.sha3_256(sealed.canonical_bytes()).digest()
                sig_ok = verify(
                    digest,
                    bytes.fromhex(sealed.signature),
                    bytes.fromhex(sealed.public_key),
                    algorithm,
                )
                if not sig_ok:
                    err = "ML-DSA signature invalid"
            except ValueError:
                err = f"unknown algorithm {sealed.algorithm}"
            except Exception as exc:  # noqa: BLE001
                err = f"signature verify failed: {exc}"

        if not chain_ok and err is None:
            err = "chain integrity broken"
        elif not merkle_ok and err is None:
            err = "merkle root mismatch"

        valid = sig_ok and chain_ok and merkle_ok
        return VerificationResult(
            valid=valid,
            signature_valid=sig_ok,
            chain_intact=chain_ok,
            merkle_root_valid=merkle_ok,
            step_count=sealed.step_count,
            error=err,
        )

    @staticmethod
    def verify_or_raise(sealed: SealedTrace) -> None:
        result = TraceVerifier.verify(sealed)
        if not result.valid:
            raise SignatureVerificationError(result.error or "verification failed")
