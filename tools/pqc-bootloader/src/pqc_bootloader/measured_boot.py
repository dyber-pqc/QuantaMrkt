"""MeasuredBoot - TPM/PCR-style chain of boot-stage hashes."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class BootStage(str, Enum):
    ROM = "rom"
    BOOTLOADER = "bootloader"
    KERNEL = "kernel"
    INITRD = "initrd"
    USERSPACE = "userspace"
    MODEL_WEIGHTS = "model-weights"


@dataclass(frozen=True)
class PCRMeasurement:
    """One measurement: stage label + SHA3-256 of the measured bytes."""

    stage: BootStage
    measured_hash: str  # hex
    measured_at: str


@dataclass
class MeasuredBoot:
    """TPM-like measurement chain.

    PCR update formula: new_pcr = SHA3-256(old_pcr || measurement).
    Every stage is extended into the PCR in order; tampering with any stage
    produces a different final PCR value.
    """

    pcr_value: str = "0" * 64
    measurements: list[PCRMeasurement] = field(default_factory=list)

    def extend(self, stage: BootStage, content: bytes) -> str:
        h = hashlib.sha3_256(content).hexdigest()
        combined = bytes.fromhex(self.pcr_value) + bytes.fromhex(h)
        self.pcr_value = hashlib.sha3_256(combined).hexdigest()
        self.measurements.append(
            PCRMeasurement(
                stage=stage,
                measured_hash=h,
                measured_at=datetime.now(timezone.utc).isoformat(),
            )
        )
        return self.pcr_value

    def reset(self) -> None:
        self.pcr_value = "0" * 64
        self.measurements.clear()
