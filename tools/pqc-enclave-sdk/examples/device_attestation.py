"""Produce and verify a DeviceAttestation for an artifact stored in an enclave vault.

Walks through:
  1. Creating a vault and storing a sample INT8 LoRA adapter.
  2. Signing a DeviceAttestation that commits to the artifact's content hash.
  3. Verifying the attestation (valid path).
  4. Tampering with the signature and showing verification fails.
"""

from __future__ import annotations

from quantumshield.identity.agent import AgentIdentity

from pqc_enclave_sdk import (
    ArtifactKind,
    DeviceAttester,
    EnclaveVault,
    InMemoryEnclaveBackend,
)


def main() -> None:
    backend = InMemoryEnclaveBackend(
        device_id="iphone-carol-demo",
        device_model="iphone-15-pro",
    )
    vault = EnclaveVault(backend=backend)
    vault.unlock()

    enc = vault.put_artifact(
        name="jailbreak-safety-lora",
        kind=ArtifactKind.LORA_ADAPTER,
        content=b"\x11" * 4096,
        version="2.0.1",
    )
    print(f"[put]     artifact_id={enc.metadata.artifact_id}")
    print(f"[hash]    sha3={enc.content_hash}")

    device_identity = AgentIdentity.create("device-attester")
    attester = DeviceAttester(
        identity=device_identity,
        device_id=backend.device_id,
        device_model=backend.device_model,
        enclave_vendor=backend.enclave_vendor,
    )
    att = attester.attest(
        artifact_id=enc.metadata.artifact_id,
        content_hash=enc.content_hash,
    )
    print(f"[attest]  signer_did={att.signer_did}")
    print(f"[attest]  algorithm={att.algorithm}")
    print(f"[verify]  valid={DeviceAttester.verify(att)}")

    # Tamper with the signature to show the PQC signature is load-bearing.
    original_signature = att.signature
    tampered = bytearray.fromhex(att.signature)
    tampered[0] ^= 0xFF
    att.signature = tampered.hex()
    print(f"[tamper]  valid_after_tamper={DeviceAttester.verify(att)}")

    # Restore and confirm verification is back to true.
    att.signature = original_signature
    print(f"[restore] valid_after_restore={DeviceAttester.verify(att)}")


if __name__ == "__main__":
    main()
