"""UpdateChain - ordered list of SignedFirmware where each links to previous by hash."""

from __future__ import annotations

from dataclasses import dataclass, field

from pqc_bootloader.errors import FirmwareRollbackError, UpdateChainError
from pqc_bootloader.firmware import SignedFirmware


@dataclass
class UpdateChain:
    """Ordered chain of SignedFirmware.

    Each link's `previous_firmware_hash` must equal the prior firmware's
    `image_hash`. The chain also enforces non-rollback: new version must be
    lexicographically >= previous version (simple semver string compare).
    """

    links: list[SignedFirmware] = field(default_factory=list)

    def add(self, signed: SignedFirmware, allow_rollback: bool = False) -> None:
        if self.links:
            prev = self.links[-1]
            if signed.previous_firmware_hash != prev.firmware.image_hash:
                raise UpdateChainError(
                    f"previous_firmware_hash {signed.previous_firmware_hash[:16]}... does not "
                    f"match prior image_hash {prev.firmware.image_hash[:16]}..."
                )
            if (
                not allow_rollback
                and signed.firmware.metadata.version < prev.firmware.metadata.version
            ):
                raise FirmwareRollbackError(
                    f"rollback blocked: {signed.firmware.metadata.version} < "
                    f"{prev.firmware.metadata.version}"
                )
        self.links.append(signed)

    def current(self) -> SignedFirmware | None:
        return self.links[-1] if self.links else None

    def verify_chain(self) -> tuple[bool, list[str]]:
        errors: list[str] = []
        prev_hash: str | None = None
        for i, link in enumerate(self.links):
            if i > 0 and link.previous_firmware_hash != prev_hash:
                errors.append(
                    f"link break at version {link.firmware.metadata.version}: "
                    f"expected prev hash {prev_hash}, got {link.previous_firmware_hash}"
                )
            prev_hash = link.firmware.image_hash
        return len(errors) == 0, errors
