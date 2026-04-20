"""Sign and verify a GPU driver module attestation with an allow-list.

Run:

    python examples/driver_attestation.py
"""

from __future__ import annotations

from quantumshield.identity.agent import AgentIdentity

from pqc_gpu_driver import (
    DriverAttestationVerifier,
    DriverAttester,
    DriverModule,
)


def main() -> None:
    # A fake nvidia.ko blob.
    driver_bytes = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"NVIDIA-GPU-DRV" * 256
    module = DriverModule(
        name="nvidia.ko",
        version="550.54.14",
        module_hash=DriverModule.hash_module_bytes(driver_bytes),
        module_size=len(driver_bytes),
        target="linux",
    )

    vendor = AgentIdentity.create("nvidia-driver-signer", capabilities=["attest"])
    attacker = AgentIdentity.create("rogue-signer", capabilities=["attest"])

    print("[*] Vendor signing driver module with ML-DSA ...")
    attester = DriverAttester(vendor)
    attestation = attester.attest(module)
    print(f"    module        = {attestation.module.name} v{attestation.module.version}")
    print(f"    module_hash   = {attestation.module.module_hash[:32]}...")
    print(f"    signer_did    = {attestation.signer_did}")
    print(f"    algorithm     = {attestation.algorithm}")
    print(f"    signed_at     = {attestation.signed_at}")

    verifier = DriverAttestationVerifier(trusted_signers={vendor.did})

    print("\n[*] Case 1: vendor attestation with correct bytes ...")
    result = verifier.verify(attestation, actual_module_bytes=driver_bytes)
    print(f"    valid   = {result.valid}")
    print(f"    trusted = {result.trusted}")
    assert result.valid

    print("\n[*] Case 2: attacker's attestation rejected by allow-list ...")
    rogue_att = DriverAttester(attacker).attest(module)
    bad = verifier.verify(rogue_att, actual_module_bytes=driver_bytes)
    print(f"    valid   = {bad.valid}")
    print(f"    error   = {bad.error}")
    assert not bad.valid

    print("\n[+] Attestation flow verified. Untrusted signers cannot load drivers.")


if __name__ == "__main__":
    main()
