"""Firmware image data structures."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class TargetDevice(str, Enum):
    """Appliance families this firmware targets."""

    AI_INFERENCE_APPLIANCE = "ai-inference-appliance"
    MEDICAL_DIAGNOSTIC = "medical-diagnostic"
    INDUSTRIAL_CONTROL = "industrial-control"
    EDGE_GATEWAY = "edge-gateway"
    MILITARY_EMBEDDED = "military-embedded"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class FirmwareMetadata:
    """Non-binary metadata describing a firmware image."""

    name: str
    version: str
    target: TargetDevice
    kernel_version: str = ""
    architecture: str = "x86_64"  # x86_64 | arm64 | riscv64 | ...
    build_id: str = ""  # git SHA, CI build id, etc.
    release_notes_url: str = ""
    min_hardware_revision: str = ""
    security_level: str = "production"  # production | development | debug

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["target"] = self.target.value
        return d


@dataclass
class FirmwareImage:
    """Raw firmware bytes + metadata + SHA3-256 hash."""

    metadata: FirmwareMetadata
    image_bytes: bytes
    image_hash: str = ""  # hex SHA3-256
    image_size: int = 0

    @staticmethod
    def hash_bytes(data: bytes) -> str:
        return hashlib.sha3_256(data).hexdigest()

    @classmethod
    def from_bytes(cls, metadata: FirmwareMetadata, data: bytes) -> FirmwareImage:
        return cls(
            metadata=metadata,
            image_bytes=data,
            image_hash=cls.hash_bytes(data),
            image_size=len(data),
        )

    @classmethod
    def from_file(cls, metadata: FirmwareMetadata, path: str) -> FirmwareImage:
        with open(path, "rb") as f:
            data = f.read()
        return cls.from_bytes(metadata, data)

    def canonical_manifest_bytes(self) -> bytes:
        """Bytes signed by the manufacturer (metadata + hash, NOT the image)."""
        payload = {
            "metadata": self.metadata.to_dict(),
            "image_hash": self.image_hash,
            "image_size": self.image_size,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def to_dict(self, include_image: bool = False) -> dict[str, Any]:
        d: dict[str, Any] = {
            "metadata": self.metadata.to_dict(),
            "image_hash": self.image_hash,
            "image_size": self.image_size,
        }
        if include_image:
            import base64

            d["image_base64"] = base64.b64encode(self.image_bytes).decode("ascii")
        return d


@dataclass
class SignedFirmware:
    """Firmware image + ML-DSA signature envelope."""

    firmware: FirmwareImage
    manufacturer_key_id: str  # fingerprint of the manufacturer public key
    signer_did: str
    algorithm: str
    signature: str  # hex
    public_key: str  # hex
    signed_at: str
    previous_firmware_hash: str = ""  # for update-chain continuity

    def to_dict(self, include_image: bool = True) -> dict[str, Any]:
        return {
            "firmware": self.firmware.to_dict(include_image=include_image),
            "manufacturer_key_id": self.manufacturer_key_id,
            "signer_did": self.signer_did,
            "algorithm": self.algorithm,
            "signature": self.signature,
            "public_key": self.public_key,
            "signed_at": self.signed_at,
            "previous_firmware_hash": self.previous_firmware_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SignedFirmware:
        import base64

        fw = data["firmware"]
        meta = fw["metadata"]
        image_bytes = b""
        if "image_base64" in fw:
            image_bytes = base64.b64decode(fw["image_base64"])
        firmware = FirmwareImage(
            metadata=FirmwareMetadata(
                name=meta["name"],
                version=meta["version"],
                target=TargetDevice(meta.get("target", "unknown")),
                kernel_version=meta.get("kernel_version", ""),
                architecture=meta.get("architecture", "x86_64"),
                build_id=meta.get("build_id", ""),
                release_notes_url=meta.get("release_notes_url", ""),
                min_hardware_revision=meta.get("min_hardware_revision", ""),
                security_level=meta.get("security_level", "production"),
            ),
            image_bytes=image_bytes,
            image_hash=fw.get("image_hash", ""),
            image_size=int(fw.get("image_size", 0)),
        )
        return cls(
            firmware=firmware,
            manufacturer_key_id=data["manufacturer_key_id"],
            signer_did=data["signer_did"],
            algorithm=data["algorithm"],
            signature=data["signature"],
            public_key=data["public_key"],
            signed_at=data["signed_at"],
            previous_firmware_hash=data.get("previous_firmware_hash", ""),
        )
