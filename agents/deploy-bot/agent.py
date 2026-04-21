"""Deploy Bot -- signs firmware for edge devices and logs every rollout."""

from __future__ import annotations

import json
from pathlib import Path

from quantumshield.identity.agent import AgentIdentity

from pqc_bootloader import (
    FirmwareImage,
    FirmwareMetadata,
    FirmwareSigner,
    FirmwareVerifier,
    TargetDevice,
)
from pqc_audit_log_fs import InferenceEvent, LogAppender, RotationPolicy


IDENTITY_FILE = Path(__file__).parent / "identity.json"


def load_identity() -> AgentIdentity:
    data = json.loads(IDENTITY_FILE.read_text())
    return AgentIdentity.create(data["name"], capabilities=data["capabilities"])


def sign_rollout(agent: AgentIdentity, image_bytes: bytes) -> tuple[str, bool]:
    metadata = FirmwareMetadata(
        name="edge-inference-fw",
        version="2026.04.20",
        target=TargetDevice.EDGE_GATEWAY,
        kernel_version="6.8",
        architecture="arm64",
        build_id="ci-build-4242",
        security_level="production",
    )
    image = FirmwareImage.from_bytes(metadata, image_bytes)
    signed = FirmwareSigner(agent).sign(image)
    result = FirmwareVerifier.verify(signed, actual_bytes=image_bytes)
    return signed.signature, result.valid


def main() -> None:
    agent = load_identity()
    print(f"[agent] {agent.did}")

    mock_image = b"\x7fELF" + b"\x00" * 2048  # stub firmware bytes
    signature, ok = sign_rollout(agent, mock_image)
    print(f"[firmware] signature={signature[:24]}...")
    print(f"[firmware] verified_locally={ok}")

    log_dir = Path(__file__).parent / "audit-log"
    with LogAppender(
        str(log_dir), agent, rotation=RotationPolicy(max_events_per_segment=100)
    ) as log:
        log.append(
            InferenceEvent.create(
                model_did=agent.did,
                model_version="1.0",
                input_bytes=mock_image,
                output_bytes=signature.encode(),
                decision_type="deployment",
                decision_label="rolled-out",
                actor_did="did:example:release-manager",
                metadata={"target": TargetDevice.EDGE_GATEWAY.value},
            )
        )
    print(f"[audit] segment sealed at {log_dir}")


if __name__ == "__main__":
    main()
