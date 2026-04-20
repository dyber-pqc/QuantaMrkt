# PQC Secure Enclave SDK

![PQC Native](https://img.shields.io/badge/PQC-Native-blue)
![ML-KEM-768](https://img.shields.io/badge/ML--KEM--768-FIPS%20203-green)
![AES-256-GCM](https://img.shields.io/badge/AES--256--GCM-FIPS%20197-green)
![iOS + Android Ready](https://img.shields.io/badge/iOS%20%2B%20Android-Ready-black)
![License](https://img.shields.io/badge/License-Apache%202.0-orange)
![Version](https://img.shields.io/badge/version-0.1.0-lightgrey)

**Quantum-safe on-device AI.** A clean Python SDK for storing AI model weights, LoRA adapters, tokenizers, and API credentials in **device secure enclaves** using **ML-KEM-768** key encapsulation + **AES-256-GCM** encryption. Pluggable backends for Apple Secure Enclave, Android StrongBox, and Qualcomm QSEE let you ship quantum-resistant on-device AI today - without waiting for the platform vendors to finish their PQC rollouts.

## The Problem

Your phone runs AI inference constantly: autocomplete, voice recognition, image classification, on-device LLMs. The model weights and API credentials those features rely on sit in device storage for **years** - Apple Neural Engine, Qualcomm AI Engine, and MediaTek APU models typically persist across OS upgrades. Today they are protected by classical cryptography baked into the secure element.

This is the **HNDL threat model** (Harvest Now, Decrypt Later) applied to on-device AI:

- An attacker who exfiltrates encrypted weight files today - from backups, compromised cloud sync, supply-chain tooling, or forensic device imaging - can store them indefinitely.
- When a cryptographically relevant quantum computer arrives, every RSA/ECDSA-wrapped symmetric key is retroactively broken and the plaintext weights fall out.
- For proprietary fine-tunes, biometric templates, and long-lived OAuth refresh tokens, "eventually decrypted" is functionally equivalent to "decrypted".

## The Solution

Wrap every on-device AI artifact in a PQC-protected envelope:

- **ML-KEM-768** (FIPS 203, NIST PQC) for the session key that the enclave unwraps.
- **AES-256-GCM** (FIPS 197) for the artifact body. Key is 32 bytes, nonce 12 bytes, tag 16 bytes.
- **SHA3-256** content hash authenticated via AES-GCM AAD - any metadata tampering breaks decryption.
- **ML-DSA** (FIPS 204) signatures for device attestations that commit to what was stored.
- Pluggable backends: `iOSEnclaveBackend`, `AndroidEnclaveBackend`, `QSEEBackend`, plus `InMemoryEnclaveBackend` for tests.

## Installation

```bash
pip install pqc-enclave-sdk
```

Development:

```bash
pip install -e ".[dev]"
```

## Quick Start

```python
from pqc_enclave_sdk import (
    ArtifactKind,
    EnclaveVault,
    InMemoryEnclaveBackend,
)

backend = InMemoryEnclaveBackend(device_id="iphone-alice", device_model="iphone-15-pro")
vault = EnclaveVault(backend=backend)

vault.unlock()
vault.put_artifact(
    name="llama-3.2-1b-int4",
    kind=ArtifactKind.MODEL_WEIGHTS,
    content=weights_bytes,
    version="1.0.0",
    app_bundle_id="com.example.localllm",
)
vault.save()
vault.lock()

# Later, in the same process or another app launch:
vault.unlock()
weights = vault.get_artifact("llama-3.2-1b-int4").content
```

## Architecture

```
  Your App                EnclaveVault            EnclaveBackend          Device Secure Enclave
  --------                ------------            --------------          ---------------------
      |                        |                         |                          |
      | put_artifact(bytes)    |                         |                          |
      | ---------------------> |                         |                          |
      |                        | 1. derive session key   |                          |
      |                        |    via ML-KEM-768       |                          |
      |                        | 2. AES-256-GCM encrypt  |                          |
      |                        |    with content-hash AAD|                          |
      |                        | 3. store_session_key ------------------------------>|
      |                        |                         | wraps w/ hardware KEK    |
      |                        | 4. save_artifacts       |                          |
      |                        | ----------------------> |                          |
      |                        |                         | persists ciphertext      |
      |                        |                         | to Keychain/Keystore     |
      |                        |                         |                          |
      | get_artifact(name)     |                         |                          |
      | ---------------------> |                         |                          |
      |                        | 5. load_session_key --------------------------------|
      |                        |    (unwrap inside SEP)                             |
      |                        | 6. AES-256-GCM decrypt  |                          |
      | <--- plaintext         |                         |                          |
```

## Artifact Kinds

| Kind | Purpose |
|---|---|
| `MODEL_WEIGHTS` | Full model weight tensors (INT4 / INT8 / FP16 on-device checkpoints). |
| `LORA_ADAPTER` | Low-rank fine-tune adapters; smaller but sensitive for proprietary tunes. |
| `TOKENIZER` | Tokenizer vocab + merges; lower-sensitivity but integrity-critical. |
| `CREDENTIAL` | API keys, OAuth tokens, auth bearer tokens. |
| `BIOMETRIC_TEMPLATE` | Encoded face / fingerprint templates. Highest sensitivity. |
| `INFERENCE_CACHE` | KV-cache blobs from prior conversations. |
| `SAFETY_MODEL` | Jailbreak classifier / content-safety adapter. |
| `OTHER` | Everything else. |

## Cryptography

| Primitive | Role | Standard |
|---|---|---|
| **ML-KEM-768** | Session-key encapsulation to the enclave's PQC public key | FIPS 203 |
| **AES-256-GCM** | Symmetric encryption of every artifact body | FIPS 197 / SP 800-38D |
| **SHA3-256** | Content hash + canonical AAD hashing | FIPS 202 |
| **ML-DSA-65 / 87** | Signatures over DeviceAttestations | FIPS 204 |

The AES-GCM AAD covers the full artifact metadata plus the content hash plus the key id - any metadata swap or cross-artifact key reuse is detected on decrypt.

## Threat Model

| Threat | Mitigation |
|---|---|
| **Device theft** (attacker has the phone) | Symmetric key never leaves the enclave. Access control requires biometrics / device unlock. |
| **HNDL on stored weights** (exfiltrated encrypted blobs today, decrypted post-CRQC) | ML-KEM-768 session-key encapsulation; AES-256-GCM (Grover-adjusted 128-bit security). |
| **Rogue app reading another app's artifacts** | `AccessPolicy.allowed_bundle_ids` filters callers; OS Keychain / Keystore access-control flags enforce at the kernel level. |
| **Stale session key** (long-lived re-use) | `DEFAULT_SESSION_TTL = 3600`; `is_unlocked` re-checks expiration on every call. |
| **Post-quantum forgery of attestation** | `DeviceAttester` signs with ML-DSA, not ECDSA. |
| **Artifact swap** (attacker substitutes one encrypted blob for another) | AAD includes `artifact_id` and content hash; decryption of a swapped blob against the wrong metadata fails. |
| **Downgrade to classical crypto** | Algorithm is baked into the AAD; a rewrite requires access to the PQC session key. |

## Backend Integration Guides

### iOS Secure Enclave (CryptoKit sketch)

```swift
import CryptoKit

// 1. Generate a non-extractable SEP key at app install.
let sepKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
    accessControl: SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet], nil)!
)

// 2. On unlock, receive the 32-byte AES-GCM key from the Python SDK
// (ideally via an ML-KEM-768 ciphertext the SEP decapsulates). Wrap it
// with the SEP key and write the sealed blob to the Keychain:
let sealedBox = try AES.GCM.seal(sessionKey, using: sepSymmetricKey)
SecItemAdd([
    kSecClass: kSecClassGenericPassword,
    kSecAttrService: "com.dyber.pqc.enclave",
    kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
    kSecValueData: sealedBox.combined!,
] as CFDictionary, nil)
```

### Android StrongBox (Kotlin sketch)

```kotlin
val spec = KeyGenParameterSpec.Builder(
    "com.dyber.pqc.enclave.session",
    KeyProperties.PURPOSE_WRAP_KEY or KeyProperties.PURPOSE_ENCRYPT
  ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
   .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
   .setIsStrongBoxBacked(true)              // Titan M / Knox Vault
   .setUserAuthenticationRequired(true)
   .setUnlockedDeviceRequired(true)
   .build()
val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
kpg.initialize(spec)
kpg.generateKeyPair()
```

### Qualcomm QSEE (Trusted App sketch)

```c
// Signed TA running inside QSEE; the Python SDK talks to it via QSEECom.
int pqc_enclave_ta_store_session(uint8_t *session_key, uint32_t len) {
    sealed_key_t sealed;
    ta_kek_wrap(g_ta_kek, session_key, len, &sealed);
    return qseecom_write_sealed_blob(&sealed);   // persists to Keystore
}
```

## API Reference

### `EnclaveVault`

| Method | Description |
|---|---|
| `unlock(ttl_seconds=3600)` | Derive a session key via ML-KEM-768 and mark the vault usable. |
| `lock()` | Wipe the session key from memory. |
| `put_artifact(name, kind, content, ...)` | AES-256-GCM encrypt and store. Returns the `EncryptedArtifact`. |
| `get_artifact(name_or_id)` | Decrypt and return `EnclaveArtifact` (metadata + plaintext). |
| `delete_artifact(name_or_id)` | Remove by name or id. |
| `list_artifacts()` | List `ArtifactMetadata` for everything in the vault. |
| `save()` | Persist the encrypted store to the backend. |
| `is_unlocked` | Property; also re-checks session expiry. |

### `EnclaveArtifact`

| Field / Method | Description |
|---|---|
| `metadata` | `ArtifactMetadata` frozen dataclass. |
| `content` | Plaintext bytes. |
| `sha3_256_hex()` | SHA3-256 of the content, hex. |
| `content_hash(bytes)` (static) | SHA3-256 helper. |

### `AccessPolicy` / `ArtifactPolicy`

| Method | Description |
|---|---|
| `AccessPolicy().add(rule)` | Attach a rule for an `ArtifactKind`. |
| `.check(metadata, caller_bundle_id)` | Raises `PolicyViolationError` on deny. |
| `ArtifactPolicy(kind, allowed_bundle_ids, require_biometric, max_uses_per_hour)` | Per-kind rule. |

### `DeviceAttester`

| Method | Description |
|---|---|
| `DeviceAttester(identity, device_id, device_model, enclave_vendor)` | Bind an `AgentIdentity` to a device. |
| `.attest(artifact_id, content_hash)` | Produce a signed `DeviceAttestation`. |
| `DeviceAttester.verify(att)` (static) | Returns True / False. |
| `DeviceAttester.verify_or_raise(att)` (static) | Raises `AttestationError` on invalid. |

### Exceptions

| Exception | When |
|---|---|
| `EnclaveSDKError` | Base class. |
| `UnknownArtifactError` | `get_artifact` / `delete_artifact` against a missing id or name. |
| `EnclaveLockedError` | Operation attempted on a locked vault. |
| `DecryptionError` | AES-GCM tag rejected ciphertext or AAD. |
| `BackendError` | iOS / Android / QSEE backend refused or is stubbed. |
| `AttestationError` | `DeviceAttester.verify_or_raise` saw an invalid signature. |
| `PolicyViolationError` | `AccessPolicy.check` denied the caller. |

## Why PQC for On-Device AI

On-device model weights live on a user's phone for **five or more years** - longer than any reasonable cryptanalytic lead time against classical RSA/ECDSA. Proprietary fine-tunes, biometric templates, and OAuth refresh tokens embedded in those artifacts are exactly the kind of data a patient adversary will harvest now to decrypt later.

This is the HNDL threat model at its most concrete: the ciphertext blob is already on the user's device, already in cloud backups, and already syncing through MDM pipes. Every one of those copies is at risk the instant a CRQC arrives. ML-KEM-768 and AES-256-GCM close that window today - no platform-vendor timeline dependency, no waiting for iOS 19 or Android 16 to ship their post-quantum Keystore updates.

## Examples

See the `examples/` directory:

- **`store_model_weights.py`** - 256 KB model weight lifecycle through an in-memory vault.
- **`store_credentials.py`** - three API credentials across three different app bundles.
- **`device_attestation.py`** - sign and verify a DeviceAttestation, and show the tamper case.

Run them:

```bash
python examples/store_model_weights.py
python examples/store_credentials.py
python examples/device_attestation.py
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src/ tests/ examples/
```

## Related

Part of the [QuantaMrkt](https://quantamrkt.com) post-quantum tooling registry. See also:

- **QuantumShield** - the underlying PQC toolkit (`AgentIdentity`, `SignatureAlgorithm`, `generate_kem_keypair`, `sign / verify`).
- **PQC Agent Wallet** - sister tool for passphrase-unlocked credential vaults.
- **PQC GPU Driver** - sister tool for keeping tensors encrypted on discrete accelerators.
- **PQC Hypervisor Attestation** - sister tool for confidential-VM memory attestation.

## License

Apache License 2.0. See [LICENSE](LICENSE).
