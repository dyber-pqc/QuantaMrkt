"""End-to-end integration tests."""

from __future__ import annotations

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_gpu_driver import (
    DriverAttestationError,
    DriverAttestationVerifier,
    DriverAttester,
    DriverModule,
    InMemoryBackend,
    TensorMetadata,
    establish_channel,
)


def test_full_flow_attest_channel_upload_download_decrypt(
    attester: DriverAttester,
    sample_module: DriverModule,
    sample_module_bytes: bytes,
    random_tensor_bytes: bytes,
) -> None:
    # 1. Attest the driver module and verify it against the allow-list.
    attestation = attester.attest(sample_module)
    verifier = DriverAttestationVerifier(trusted_signers={attester.identity.did})
    verifier.verify_or_raise(attestation, actual_module_bytes=sample_module_bytes)

    # 2. Establish encrypted CPU<->GPU channel.
    cpu, gpu = establish_channel()

    # 3. Encrypt tensor on the CPU side.
    meta = TensorMetadata(
        tensor_id="llama-layer-0-w",
        name="layer_0.self_attn.q_proj.weight",
        dtype="float32",
        shape=(len(random_tensor_bytes) // 4,),
        size_bytes=len(random_tensor_bytes),
        transfer_direction="cpu_to_gpu",
    )
    enc = cpu.encrypt_tensor(random_tensor_bytes, meta)

    # 4. Upload to the backend (encrypted bytes only).
    backend = InMemoryBackend()
    handle = backend.upload(enc)

    # 5. Download from backend on GPU side.
    pulled = backend.download(handle)

    # 6. GPU side decrypts - must match original plaintext bit-for-bit.
    decrypted = gpu.decrypt_tensor(pulled)
    assert decrypted == random_tensor_bytes

    backend.free(handle)


def test_byzantine_untrusted_signer_rejected(
    untrusted_identity: AgentIdentity,
    trusted_identity: AgentIdentity,
    sample_module: DriverModule,
    sample_module_bytes: bytes,
) -> None:
    # Attacker (untrusted) attempts to attest a module.
    rogue_attester = DriverAttester(untrusted_identity)
    rogue_attestation = rogue_attester.attest(sample_module)

    # Verifier only trusts the vendor identity.
    verifier = DriverAttestationVerifier(trusted_signers={trusted_identity.did})

    result = verifier.verify(
        rogue_attestation, actual_module_bytes=sample_module_bytes
    )
    # Signature verifies, hash matches - but signer is not trusted.
    assert result.valid is False
    assert result.trusted is False
    assert "not in trusted set" in (result.error or "")

    # verify_or_raise should also refuse.
    with pytest.raises(DriverAttestationError):
        verifier.verify_or_raise(
            rogue_attestation, actual_module_bytes=sample_module_bytes
        )
