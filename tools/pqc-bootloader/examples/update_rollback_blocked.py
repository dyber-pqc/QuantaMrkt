"""Example: UpdateChain blocks a rollback from v1.0 to v0.9.

Rollback attacks abuse legitimately-signed old firmware to re-introduce known
vulnerabilities. UpdateChain enforces monotonic versions by default. Set
`allow_rollback=True` only for emergency break-glass scenarios.
"""

from __future__ import annotations

from quantumshield.identity.agent import AgentIdentity

from pqc_bootloader import (
    FirmwareImage,
    FirmwareMetadata,
    FirmwareRollbackError,
    FirmwareSigner,
    TargetDevice,
    UpdateChain,
)


def build(name: str, version: str, payload: bytes) -> FirmwareImage:
    meta = FirmwareMetadata(
        name=name,
        version=version,
        target=TargetDevice.AI_INFERENCE_APPLIANCE,
    )
    return FirmwareImage.from_bytes(meta, payload)


def main() -> None:
    signer = FirmwareSigner(AgentIdentity.create("acme-appliance-vendor"))
    chain = UpdateChain()

    v1 = signer.sign(build("acme-inference-os", "1.0.0", b"v1.0 payload"))
    chain.add(v1)
    print(f"[chain] added v{v1.firmware.metadata.version} (hash={v1.firmware.image_hash[:16]}...)")

    # Attacker tries to push v0.9 as the next update (rollback).
    v0 = signer.sign(
        build("acme-inference-os", "0.9.0", b"v0.9 payload"),
        previous_firmware_hash=v1.firmware.image_hash,
    )
    try:
        chain.add(v0)
    except FirmwareRollbackError as exc:
        print(f"[chain] BLOCKED v{v0.firmware.metadata.version}: {exc}")

    # Forward update is fine.
    v2 = signer.sign(
        build("acme-inference-os", "1.1.0", b"v1.1 payload"),
        previous_firmware_hash=v1.firmware.image_hash,
    )
    chain.add(v2)
    print(f"[chain] added v{v2.firmware.metadata.version} (hash={v2.firmware.image_hash[:16]}...)")

    ok, errors = chain.verify_chain()
    print(f"[chain] verify_chain: ok={ok} errors={errors}")
    print(f"[chain] current version = {chain.current().firmware.metadata.version}")


if __name__ == "__main__":
    main()
