# pqc-bootloader

[![PQC Native](https://img.shields.io/badge/PQC-Native-6f42c1)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![ML-DSA-65](https://img.shields.io/badge/Signature-ML--DSA--65-0a7)](https://csrc.nist.gov/pubs/fips/204/final)
[![SHA3-256](https://img.shields.io/badge/Hash-SHA3--256-0a7)](https://csrc.nist.gov/pubs/fips/202/final)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-lightgrey)](pyproject.toml)

**PQC-native signed-boot framework for AI appliances.** Edge inference servers deployed in hospitals, factories, and military installations have 10-15 year operational lifespans. Firmware signed today with RSA-2048 or ECDSA-P256 is a Harvest-Now-Decrypt-Later target: a cryptographically relevant quantum computer (CRQC) in the 2030-2035 window can forge a signature on a malicious firmware image and push it into a fleet of appliances that still believe the original root-of-trust is valid. `pqc-bootloader` is a drop-in cryptographic layer that replaces `RSA_verify()` in your bootloader with `ML_DSA_verify()`, ships a manufacturer key-ring, enforces non-rollback via an update chain, and produces a TPM-style measured-boot PCR — so an appliance built today still has a defensible root-of-trust in 2040.

## Install

```bash
pip install pqc-bootloader
```

## Quick start

```python
from quantumshield.identity.agent import AgentIdentity
from pqc_bootloader import (
    FirmwareImage, FirmwareMetadata, TargetDevice,
    FirmwareSigner, FirmwareVerifier,
    KeyRing, MeasuredBoot, BootStage, BootAttestationLog,
)

# --- manufacturer ---
mfr = AgentIdentity.create("acme-appliance-vendor")
signer = FirmwareSigner(mfr)

metadata = FirmwareMetadata(
    name="acme-inference-os", version="1.2.3",
    target=TargetDevice.AI_INFERENCE_APPLIANCE,
)
firmware = FirmwareImage.from_bytes(metadata, open("firmware.bin", "rb").read())
signed = signer.sign(firmware)

# --- appliance ---
ring = KeyRing()
ring.add(mfr.signing_keypair.public_key.hex(),
         mfr.signing_keypair.algorithm.value, "Acme Inc.")

result = FirmwareVerifier.verify(signed,
                                 actual_bytes=firmware.image_bytes,
                                 key_ring=ring)
assert result.valid

mb = MeasuredBoot()
mb.extend(BootStage.BOOTLOADER, open("/boot/bootloader.bin", "rb").read())
mb.extend(BootStage.KERNEL,     open("/boot/vmlinuz", "rb").read())
mb.extend(BootStage.INITRD,     open("/boot/initrd.img", "rb").read())

log = BootAttestationLog()
log.log_accept(firmware.metadata.name, firmware.metadata.version,
               firmware.image_hash, pcr_value_after=mb.pcr_value)
```

## Architecture

```
  +------------------+       ML-DSA-65 sign            +--------------------+
  |   Manufacturer   |-------------------------------->|  SignedFirmware    |
  |  AgentIdentity   |   (metadata + SHA3-256 hash)    |  .to_dict() bytes  |
  +------------------+                                 +--------------------+
                                                                 |
                                                                 v
                                        +----------------------------------+
                                        |   Distribution (OTA / USB / CDN) |
                                        +----------------------------------+
                                                                 |
                                                                 v
  +----------------+    reads    +-----------+   check    +-------------------+
  |   Boot ROM     |------------>| KeyRing   |<-----------| manufacturer_key_id|
  |  (U-Boot/GRUB  |             | allow-list|            +-------------------+
  |   fork)        |             +-----------+                    |
  +----------------+                   |                          |
                                       v                          v
                             +------------------+     +-----------------------+
                             | FirmwareVerifier |<----| SHA3-256 hash recompute|
                             |  (ML_DSA_verify) |     +-----------------------+
                             +------------------+
                                       |
                        +--------------+--------------+
                        |                             |
                  ACCEPT  v                           v  REJECT
             +-------------------+          +-------------------+
             |  MeasuredBoot     |          | BootAttestationLog|
             |  PCR chain        |          |  log_reject(...)  |
             |  bootloader-kernel|          |  -> halt/fallback |
             |  -initrd-userspace|          +-------------------+
             +-------------------+
                        |
                        v
             +-------------------+
             | BootAttestationLog|
             |  log_accept(...,  |
             |  pcr_value_after) |
             +-------------------+
```

## Cryptography

| Primitive     | Algorithm                | Role                                 |
| ------------- | ------------------------ | ------------------------------------ |
| Signature     | ML-DSA-65 (FIPS 204)     | Firmware manifest signatures         |
| Hash          | SHA3-256 (FIPS 202)      | Firmware image hash + PCR extend     |
| Identity      | `quantumshield` DID      | Manufacturer + device identifiers    |
| Key fingerprint | SHA3-256 of public key | `manufacturer_key_id` in KeyRing     |

The manufacturer signs a *canonical manifest* (JSON, sort_keys, no whitespace) covering the firmware metadata, SHA3-256 image hash, and image size — not the image bytes themselves. The bootloader recomputes the manifest from the delivered blob, then verifies the ML-DSA signature over that manifest. This means the signature is small and constant-size regardless of firmware size (which can be hundreds of MB for inference OSes with bundled model weights).

## Threat model

| Threat                          | Mitigation                                                                 |
| ------------------------------- | -------------------------------------------------------------------------- |
| **Firmware HNDL**               | ML-DSA-65 signatures are quantum-safe; CRQC cannot forge them              |
| **Rogue update** (signed by attacker with their own key) | `KeyRing` allow-list; untrusted `manufacturer_key_id` rejected |
| **Rollback attack** (legit older firmware re-deployed to re-introduce CVE) | `UpdateChain.add()` blocks when `new.version < prev.version` unless `allow_rollback=True` |
| **Stolen manufacturer key**     | `KeyRing.revoke(key_id, reason)` marks entry; `is_trusted()` returns False. Rotate to a new manufacturer key and re-sign in-field firmware. |
| **Measured-boot tamper**        | `MeasuredBoot.extend()` chains `SHA3(prev_pcr \|\| measurement)`; any swap of bootloader/kernel/initrd/userspace yields a different final PCR, detectable by remote attestation |
| **Image hash substitution** (manifest signed, but delivered image is different) | `FirmwareVerifier.verify(signed, actual_bytes=...)` recomputes SHA3-256 over the delivered blob and rejects on mismatch |
| **Manifest-only replay** (copy metadata from one device's firmware to another) | `target` + `min_hardware_revision` fields in `FirmwareMetadata` are part of the signed manifest |

## Key-ring lifecycle

```python
from pqc_bootloader import KeyRing

ring = KeyRing()

# 1. provisioning (at factory burn-in)
entry = ring.add(
    public_key_hex=mfr_pubkey_hex,
    algorithm="ML-DSA-65",
    manufacturer="Acme Appliances Inc.",
    role="firmware-signer",
)
ring.add(supplier_pubkey_hex, "ML-DSA-65", "Contoso Systems")  # multi-vendor supply chain

# 2. check at boot
if ring.is_trusted(signed.manufacturer_key_id):
    ...

# 3. revocation (e.g. HSM compromise disclosed)
ring.revoke(entry.key_id, reason="Acme HSM compromise CVE-2032-00001")

# 4. export for audit / mirroring
print(ring.export_json())
```

The key-ring is designed to live in OTP / fuses or in a sealed TPM NV-index. Revocation entries persist; a revoked key is never re-trusted — rotate to a fresh key and re-sign in-field firmware instead.

## Integration guide

`pqc-bootloader` is a cryptographic library. Real integration involves forking one of the classical signed-boot stacks:

| Stack        | What to replace                                                          |
| ------------ | ------------------------------------------------------------------------ |
| **U-Boot**   | `FIT_SIGNATURE_ALGO` hook: swap `rsa,sha256` for a custom `mldsa,sha3-256` that shells out to a small C binding around `FirmwareVerifier.verify`. Pin the manufacturer public key in `u-boot.dtb`. |
| **GRUB 2**   | Replace `grub-pgp` verifier with a PQC verifier module; the `KeyRing` exports a GPG-compatible JSON that your module parses. |
| **coreboot** | Vboot v2: replace `RSA2048EXP3` kernel vboot key with an ML-DSA-65 key; update `firmware/2lib/2rsa.c` signature-verify call-site. |
| **UEFI Secure Boot** | Add ML-DSA-65 as an allowed signature algorithm in `db`; bootloader consumes `pqc-bootloader` output envelopes. |

In all cases the library gives you (a) the wire-format (`SignedFirmware.to_dict() / from_dict`), (b) the canonical manifest bytes (`FirmwareImage.canonical_manifest_bytes`), and (c) the cryptographic primitives (via `quantumshield.core.signatures.verify`). The bootloader-specific work is wiring these into the existing verify call-site.

## API reference

### `FirmwareMetadata`

Dataclass. `name`, `version`, `target` (`TargetDevice` enum), plus optional `kernel_version`, `architecture`, `build_id`, `release_notes_url`, `min_hardware_revision`, `security_level`.

### `FirmwareImage`

- `FirmwareImage.from_bytes(metadata, data) -> FirmwareImage`
- `FirmwareImage.from_file(metadata, path) -> FirmwareImage`
- `FirmwareImage.hash_bytes(data) -> str` — SHA3-256 hex
- `firmware.canonical_manifest_bytes() -> bytes` — signed payload
- `firmware.to_dict(include_image=False) -> dict`

### `FirmwareSigner`

- `FirmwareSigner(identity)` — construct from a `quantumshield.AgentIdentity`
- `signer.key_id -> str` — SHA3-256 of public key
- `signer.sign(firmware, previous_firmware_hash="") -> SignedFirmware`

### `FirmwareVerifier`

- `FirmwareVerifier.verify(signed, actual_bytes=None, key_ring=None) -> VerificationResult`
  - `actual_bytes`: if supplied, recomputes SHA3-256 and checks against `signed.firmware.image_hash`
  - `key_ring`: if supplied, refuses untrusted `manufacturer_key_id`
- `FirmwareVerifier.verify_or_raise(...)` — same but raises `FirmwareVerificationError`

`VerificationResult` fields: `valid`, `signature_valid`, `hash_consistent`, `key_trusted`, `signer_did`, `firmware_name`, `error`.

### `KeyRing`

- `ring.add(public_key_hex, algorithm, manufacturer, role="firmware-signer") -> KeyRingEntry`
- `ring.revoke(key_id, reason)`
- `ring.get(key_id) -> KeyRingEntry` (raises `UnknownKeyError`)
- `ring.is_trusted(key_id) -> bool`
- `ring.list_entries() -> list[KeyRingEntry]`
- `ring.export_json() -> str`
- `KeyRing.fingerprint(public_key_hex) -> str`

### `UpdateChain`

- `chain.add(signed, allow_rollback=False)` — raises `UpdateChainError` / `FirmwareRollbackError`
- `chain.current() -> SignedFirmware | None`
- `chain.verify_chain() -> tuple[bool, list[str]]`

### `MeasuredBoot`

- `mb.extend(stage, content) -> str` — returns new PCR hex
- `mb.reset()`
- `mb.pcr_value: str` / `mb.measurements: list[PCRMeasurement]`

`BootStage` enum: `ROM | BOOTLOADER | KERNEL | INITRD | USERSPACE | MODEL_WEIGHTS`.

### `BootAttestationLog`

- `log.log_accept(firmware_name, firmware_version, firmware_hash, reason="", device_id="", pcr_value_after="")`
- `log.log_reject(firmware_name, firmware_version, firmware_hash, reason, device_id="")`
- `log.entries(limit=100, decision=None) -> list[BootAttemptEntry]`
- `log.export_json() -> str`

### Exceptions

`BootloaderError` > `{FirmwareVerificationError, UnknownKeyError, UpdateChainError, MeasuredBootError, KeyRingError}`, plus `FirmwareRollbackError(UpdateChainError)`.

## Why PQC for bootloaders

- **Deployment lifespan vs. quantum timeline.** NIST expects ML-DSA migration mandatory for federal signed firmware by 2030-2033. Medical imaging systems, factory PLCs, and military embedded platforms built today will still be in service in 2038-2040. Signing those with RSA/ECDSA is a shipped-in-vault HNDL target.
- **One-shot root of trust.** Unlike TLS, bootloader keys usually can't be rotated over the air — they're burned into fuses. A bootloader signed with a classical key you can't rotate is a permanent liability.
- **Supply-chain blast radius.** A forged firmware signature doesn't compromise one session; it owns the device for its operational life. An adversary harvesting today's signed update and forging it at Q-day can replace the kernel on every deployed unit at once.
- **Measured boot is orthogonal to signing.** Even with PQC signatures, an attacker who tampers with the kernel after verify-and-load is caught by the PCR chain — which remote attestation consumers (RA verifiers, TEE attestors) can validate.

## Examples

- [`examples/sign_and_boot.py`](examples/sign_and_boot.py) — end-to-end factory sign -> appliance boot -> measured PCR -> audit accept
- [`examples/rogue_firmware_rejected.py`](examples/rogue_firmware_rejected.py) — attacker-signed firmware rejected by key-ring
- [`examples/update_rollback_blocked.py`](examples/update_rollback_blocked.py) — `UpdateChain` blocks v1.0 -> v0.9

## License

Apache-2.0. See [LICENSE](LICENSE).
