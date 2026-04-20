"""Firmware signing and verification using ML-DSA."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.signatures import sign, verify
from quantumshield.identity.agent import AgentIdentity

from pqc_bootloader.errors import FirmwareVerificationError
from pqc_bootloader.firmware import FirmwareImage, SignedFirmware
from pqc_bootloader.key_ring import KeyRing


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of verifying a SignedFirmware."""

    valid: bool
    signature_valid: bool
    hash_consistent: bool
    key_trusted: bool
    signer_did: str | None
    firmware_name: str | None
    error: str | None = None


class FirmwareSigner:
    """Signs firmware images with a fixed manufacturer AgentIdentity.

    Usage:
        manufacturer = AgentIdentity.create("acme-appliance-vendor")
        signer = FirmwareSigner(manufacturer)
        signed = signer.sign(firmware)
        # distribute signed.to_dict() with the firmware update
    """

    def __init__(self, identity: AgentIdentity) -> None:
        self.identity = identity

    @property
    def key_id(self) -> str:
        """Fingerprint of the manufacturer public key."""
        return hashlib.sha3_256(self.identity.signing_keypair.public_key).hexdigest()

    def sign(
        self,
        firmware: FirmwareImage,
        previous_firmware_hash: str = "",
    ) -> SignedFirmware:
        """Produce a SignedFirmware envelope for the given FirmwareImage."""
        manifest = firmware.canonical_manifest_bytes()
        sig = sign(manifest, self.identity.signing_keypair)
        return SignedFirmware(
            firmware=firmware,
            manufacturer_key_id=self.key_id,
            signer_did=self.identity.did,
            algorithm=self.identity.signing_keypair.algorithm.value,
            signature=sig.hex(),
            public_key=self.identity.signing_keypair.public_key.hex(),
            signed_at=datetime.now(timezone.utc).isoformat(),
            previous_firmware_hash=previous_firmware_hash,
        )


class FirmwareVerifier:
    """Validates SignedFirmware envelopes against a manufacturer key-ring.

    The verifier can operate in three modes:
      1. Pure signature check (no actual_bytes, no key_ring).
      2. Hash-consistency check (actual_bytes supplied - compares SHA3-256
         of the delivered image against the signed image_hash).
      3. Trust check (key_ring supplied - refuses firmware signed by keys
         not in the manufacturer allow-list).
    """

    @staticmethod
    def verify(
        signed: SignedFirmware,
        actual_bytes: bytes | None = None,
        key_ring: KeyRing | None = None,
    ) -> VerificationResult:
        firmware_name = signed.firmware.metadata.name
        signer_did = signed.signer_did

        # --- hash-consistency check -------------------------------------
        hash_consistent = True
        if actual_bytes is not None:
            actual_hash = FirmwareImage.hash_bytes(actual_bytes)
            if actual_hash != signed.firmware.image_hash:
                return VerificationResult(
                    valid=False,
                    signature_valid=False,
                    hash_consistent=False,
                    key_trusted=False,
                    signer_did=signer_did,
                    firmware_name=firmware_name,
                    error=(
                        f"image hash mismatch (expected "
                        f"{signed.firmware.image_hash[:16]}..., got "
                        f"{actual_hash[:16]}...)"
                    ),
                )

        # --- trust check (key-ring) -------------------------------------
        key_trusted = True
        if key_ring is not None:
            if not key_ring.is_trusted(signed.manufacturer_key_id):
                return VerificationResult(
                    valid=False,
                    signature_valid=False,
                    hash_consistent=hash_consistent,
                    key_trusted=False,
                    signer_did=signer_did,
                    firmware_name=firmware_name,
                    error=(
                        f"manufacturer key {signed.manufacturer_key_id[:16]}... "
                        f"not trusted by key-ring"
                    ),
                )
            # Also verify that the embedded public_key matches the key_id
            expected_kid = KeyRing.fingerprint(signed.public_key)
            if expected_kid != signed.manufacturer_key_id:
                return VerificationResult(
                    valid=False,
                    signature_valid=False,
                    hash_consistent=hash_consistent,
                    key_trusted=False,
                    signer_did=signer_did,
                    firmware_name=firmware_name,
                    error=(
                        "embedded public_key fingerprint does not match "
                        "manufacturer_key_id"
                    ),
                )

        # --- signature check --------------------------------------------
        try:
            algorithm = SignatureAlgorithm(signed.algorithm)
        except ValueError:
            return VerificationResult(
                valid=False,
                signature_valid=False,
                hash_consistent=hash_consistent,
                key_trusted=key_trusted,
                signer_did=signer_did,
                firmware_name=firmware_name,
                error=f"unknown algorithm {signed.algorithm}",
            )

        manifest = signed.firmware.canonical_manifest_bytes()
        try:
            sig_ok = verify(
                manifest,
                bytes.fromhex(signed.signature),
                bytes.fromhex(signed.public_key),
                algorithm,
            )
        except Exception as exc:  # noqa: BLE001
            return VerificationResult(
                valid=False,
                signature_valid=False,
                hash_consistent=hash_consistent,
                key_trusted=key_trusted,
                signer_did=signer_did,
                firmware_name=firmware_name,
                error=f"signature verify failed: {exc}",
            )

        if not sig_ok:
            return VerificationResult(
                valid=False,
                signature_valid=False,
                hash_consistent=hash_consistent,
                key_trusted=key_trusted,
                signer_did=signer_did,
                firmware_name=firmware_name,
                error="invalid ML-DSA signature",
            )

        return VerificationResult(
            valid=True,
            signature_valid=True,
            hash_consistent=hash_consistent,
            key_trusted=key_trusted,
            signer_did=signer_did,
            firmware_name=firmware_name,
        )

    @staticmethod
    def verify_or_raise(
        signed: SignedFirmware,
        actual_bytes: bytes | None = None,
        key_ring: KeyRing | None = None,
    ) -> VerificationResult:
        """Like verify() but raises FirmwareVerificationError on failure."""
        result = FirmwareVerifier.verify(signed, actual_bytes, key_ring)
        if not result.valid:
            raise FirmwareVerificationError(
                f"firmware {result.firmware_name!r} failed verification: {result.error}"
            )
        return result
