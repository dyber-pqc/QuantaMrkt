# PQC GPU Driver

![PQC Native](https://img.shields.io/badge/PQC-Native-blue)
![ML-KEM-768](https://img.shields.io/badge/ML--KEM--768-FIPS%20203-green)
![ML-DSA-65](https://img.shields.io/badge/ML--DSA--65-FIPS%20204-green)
![AES-256-GCM](https://img.shields.io/badge/AES--256--GCM-NIST%20SP%20800--38D-teal)
![License](https://img.shields.io/badge/License-Apache%202.0-orange)
![Version](https://img.shields.io/badge/version-0.1.0-lightgrey)

**Post-quantum confidential computing for the PCIe bus.** Modern AI inference ships multi-gigabyte model weights and activations between CPU and GPU over PCIe. That bus is visible to the host OS, the hypervisor, and the kernel's GPU driver. A malicious host or curious operator can trivially snoop or rewrite the bytes in flight — and even the NVIDIA Confidential Computing story on Hopper (H100/H200) relies on classical crypto that a future CRQC can retroactively forge. This library is the **post-quantum cryptographic envelope** — ML-KEM-768 channel keys, AES-256-GCM per-transfer, ML-DSA driver attestation — that a confidential-inference framework plugs its real CUDA / ROCm / vendor primitives into.

## The Problem

GPU driver stacks (the NVIDIA kernel module, AMD `amdgpu`, the vendor's userland runtime) move tensor bytes between CPU RAM and device memory. In the default configuration:

- **Plaintext traverses PCIe.** A hypervisor with DMA introspection, a VFIO passthrough attacker, or a kernel-module rootkit can read every byte.
- **Driver modules are loaded with classical signatures.** NVIDIA's `modinfo` signatures and secure-boot chains rely on RSA / ECDSA that Shor's algorithm breaks.
- **Key establishment for confidential computing uses ECDH.** A recorded session today can be passively decrypted once a CRQC exists.

A confidential AI workload needs more than "the GPU is in a TEE": it needs a post-quantum envelope around every tensor hitting the bus, and a cryptographic check on every driver that touches those tensors.

## The Solution

- **ML-KEM-768** establishes a fresh 32-byte channel key between CPU and GPU at module-load time. In production this is `ML-KEM.Decapsulate` run on both sides; the library delegates to [`quantumshield`](https://github.com/dyber-pqc/quantumshield) for the keypair.
- **AES-256-GCM** encrypts every tensor transfer. The authentication tag binds the ciphertext to `TensorMetadata + sequence_number` via AAD, so tampering with either the bytes or the metadata surfaces as a `DecryptionError`.
- **ML-DSA-65** signs every GPU driver / kernel module before load. The verifier checks both the signature and an allow-list of trusted signer DIDs.
- **`ChannelSession`** enforces strictly monotonic sequence numbers and tracks recent nonces, rejecting replays.
- **Pluggable backends** — the library never touches real device memory. Backends do, using `cuMemcpy` / `cuMemAlloc` / `CUDA-IPC` or `hipMemcpy` / `hipMalloc` / `HIP-IPC`. An `InMemoryBackend` ships for tests.

## Installation

```bash
pip install pqc-gpu-driver
```

Development:

```bash
pip install -e ".[dev]"
```

## Quick Start

```python
from pqc_gpu_driver import (
    InMemoryBackend,
    TensorMetadata,
    establish_channel,
)

# 1. Bring up an encrypted CPU<->GPU channel (ML-KEM-768 -> AES-256-GCM key).
cpu, gpu = establish_channel(cpu_side_label="inference-host",
                             gpu_side_label="h100-0")

# 2. Encrypt a tensor on the CPU side.
tensor_bytes = b"\x01" * 4096
meta = TensorMetadata(
    tensor_id="layer_0.q_proj",
    name="model.layers.0.self_attn.q_proj.weight",
    dtype="float32",
    shape=(1024,),
    size_bytes=len(tensor_bytes),
)
enc = cpu.encrypt_tensor(tensor_bytes, meta)

# 3. Move the ciphertext through a GPU backend. Backends only carry bytes,
#    they never see plaintext.
backend = InMemoryBackend()
handle = backend.upload(enc)
pulled = backend.download(handle)

# 4. Decrypt on the GPU side. AES-GCM verifies AAD + ciphertext + sequence.
plaintext = gpu.decrypt_tensor(pulled)
assert plaintext == tensor_bytes
```

Driver attestation before a kernel module is allowed to load:

```python
from quantumshield.identity.agent import AgentIdentity
from pqc_gpu_driver import (
    DriverAttestationVerifier,
    DriverAttester,
    DriverModule,
)

driver_bytes = open("/lib/modules/.../nvidia.ko", "rb").read()
module = DriverModule(
    name="nvidia.ko",
    version="550.54.14",
    module_hash=DriverModule.hash_module_bytes(driver_bytes),
    module_size=len(driver_bytes),
)

vendor = AgentIdentity.create("nvidia-driver-signer")
attestation = DriverAttester(vendor).attest(module)

verifier = DriverAttestationVerifier(trusted_signers={vendor.did})
verifier.verify_or_raise(attestation, actual_module_bytes=driver_bytes)
```

## Architecture

```
+------------------------------+                    +------------------------------+
|  CPU (inference host)        |                    |  GPU (confidential device)   |
|                              |                    |                              |
|  ChannelSession (cpu)        |   ML-KEM-768       |  ChannelSession (gpu)        |
|    symmetric_key  <----------+  handshake/KDF  +----------->  symmetric_key      |
|    next_send_seq             |                    |    last_recv_seq             |
|                              |                    |    _used_nonces_recent       |
|      |                       |                    |        ^                     |
|      v                       |                    |        |                     |
|  AES-256-GCM encrypt         |                    |  AES-256-GCM decrypt +       |
|    + AAD(metadata || seq)    |                    |    AAD check + replay check  |
|      |                       |                    |        ^                     |
|      v                       |                    |        |                     |
|  EncryptedTensor  --+        |                    |   EncryptedTensor            |
|                     |        |                    |        ^                     |
|                     v        |                    |        |                     |
|                 GPUBackend.upload()  PCIe bus     |   GPUBackend.download()      |
|                     |        |    (ciphertext     |        |                     |
|                     +--------+---->  only)  ------+--------+                     |
+------------------------------+                    +------------------------------+

                    DriverAttester  --(ML-DSA-65 sign)-->  DriverAttestation
                                                                  |
                                                                  v
                                              DriverAttestationVerifier
                                              - module hash check
                                              - ML-DSA signature check
                                              - trusted-signers allow-list
```

## Cryptography

| Primitive                  | Purpose                                           | Algorithm          |
| -------------------------- | ------------------------------------------------- | ------------------ |
| CPU/GPU channel key        | Establish fresh 32-byte symmetric key             | ML-KEM-768         |
| Per-tensor encryption      | Confidentiality + integrity of tensor bytes       | AES-256-GCM        |
| AAD over metadata          | Bind `TensorMetadata` + sequence number           | AES-GCM tag        |
| Driver attestation         | Bind driver bytes to a trusted signer DID         | ML-DSA-65          |
| Content / canonical digest | Module hash and attestation canonical digest      | SHA3-256           |

Signing and KEM keys are delegated to [`quantumshield`](https://github.com/dyber-pqc/quantumshield), which prefers real `liboqs` ML-KEM / ML-DSA when available and falls back to a transitional implementation otherwise.

## Threat Model

| Adversary capability                                               | Coverage                                                                   |
| ------------------------------------------------------------------ | -------------------------------------------------------------------------- |
| Sniffs PCIe DMA to read model weights in transit                   | Blocked — every transfer is AES-256-GCM ciphertext.                        |
| Rewrites bytes in a DMA buffer mid-transfer                        | Detected — GCM tag binds ciphertext; decrypt raises `DecryptionError`.     |
| Tampers with tensor metadata while preserving ciphertext           | Detected — metadata is in AAD, decrypt fails.                              |
| Swaps in a backdoored `nvidia.ko` / `amdgpu.ko` at load time       | Blocked — driver hash must match the ML-DSA-signed `DriverAttestation`.    |
| Ships a driver signed by an untrusted key                          | Blocked — verifier's `trusted_signers` allow-list filters signer DIDs.     |
| Replays an old `EncryptedTensor` to corrupt state                  | Blocked — strictly-monotonic sequence number + nonce cache.                |
| Reuses an expired channel key                                      | Blocked — `ChannelSession.is_valid()` enforces TTL.                        |
| Records traffic today, decrypts in 2035 with a CRQC                | Blocked — ML-KEM + ML-DSA are post-quantum.                                |
| Compromises the CPU-side host OS fully                             | Out of scope — mitigate with SEV-SNP / TDX around the inference workload.  |
| Extracts the session key from GPU device RAM                       | Out of scope — mitigate with H100/H200 Confidential Computing enclaves.    |

## Backend Integration Guide

The library defines a minimal interface:

```python
class GPUBackend(ABC):
    name: str
    device_type: str

    def upload(self, tensor: EncryptedTensor) -> str: ...
    def download(self, device_handle: str) -> EncryptedTensor: ...
    def free(self, device_handle: str) -> None: ...
    def device_info(self) -> dict: ...
```

Backends move opaque ciphertext. They never call `decrypt_tensor()` — that is the session's job, run inside the trusted compute boundary.

### NVIDIA CUDA (`CUDABackend`)

The shipped `CUDABackend` is a stub. A real integration:

1. Opens a CUDA context via `cuInit` / `cuCtxCreate` for the target device (H100 / H200 with Confidential Computing enabled).
2. On `upload`: `cuMemAlloc` a device buffer sized for the ciphertext, then `cuMemcpyHtoD` the hex-decoded ciphertext bytes. Register a `CUDA-IPC` handle if cross-process.
3. On `download`: `cuMemcpyDtoH` the buffer back to pinned host memory.
4. On `free`: `cuMemFree` plus drop the IPC handle.
5. Keep bytes encrypted at rest on device; plaintext lives only inside the confidential-computing enclave.

### AMD ROCm (`ROCmBackend`)

Mirror the CUDA flow with `hipInit` / `hipMalloc` / `hipMemcpy` / `hipFree` and `HIP-IPC`.

### Your own backend

Subclass `GPUBackend`, implement the four methods, and pass an instance through the upload / download path. The session handles encryption, AAD binding, and replay protection uniformly.

## API Reference

### Data types

| Class                | Description                                                      |
| -------------------- | ---------------------------------------------------------------- |
| `TensorMetadata`     | Non-secret tensor descriptor used as AAD.                        |
| `EncryptedTensor`    | Metadata + nonce + AES-GCM ciphertext + sequence number.         |
| `DriverModule`       | Driver binary summary: `(name, version, module_hash, size)`.     |
| `DriverAttestation`  | ML-DSA-signed claim about a `DriverModule`.                      |
| `VerificationResult` | Pass/fail breakdown with `error` detail.                         |

### Channel

| Symbol                           | Purpose                                                      |
| -------------------------------- | ------------------------------------------------------------ |
| `establish_channel(...)`         | Produce a matched `(cpu_session, gpu_session)` pair.         |
| `ChannelSession.encrypt_tensor`  | Encrypt tensor bytes + bind metadata via AAD.                |
| `ChannelSession.decrypt_tensor`  | Decrypt, verify AAD, enforce monotonic sequence + nonce.     |
| `ChannelSession.is_valid`        | Check TTL has not elapsed.                                   |

### Driver attestation

| Symbol                                    | Purpose                                             |
| ----------------------------------------- | --------------------------------------------------- |
| `DriverAttester.attest`                   | Produce an ML-DSA-signed `DriverAttestation`.       |
| `DriverAttestationVerifier.verify`        | Return a `VerificationResult`.                      |
| `DriverAttestationVerifier.verify_or_raise` | Raise `DriverAttestationError` on failure.        |

### Backends

| Class              | Use                                                       |
| ------------------ | --------------------------------------------------------- |
| `InMemoryBackend`  | Reference / tests / tutorials.                            |
| `CUDABackend`      | Stub for NVIDIA CUDA (plug into `cuMemcpy` / CUDA-IPC).   |
| `ROCmBackend`      | Stub for AMD ROCm (plug into `hipMemcpy` / HIP-IPC).      |

### Exceptions

`GPUDriverError` -> `ChannelEstablishmentError`, `ChannelExpiredError`, `NonceReplayError`, `DecryptionError`, `DriverAttestationError`, `BackendError`.

## Why PQC Matters for GPU Drivers

Confidential GPU computing on H100 and H200 today relies on classical primitives: RSA / ECDSA driver signatures, ECDH for the session key between CPU and GPU enclaves, SHA-256 content hashes. Each of those is a direct target for a CRQC running Shor's algorithm. A session key negotiated in 2026 can be recovered from a recorded PCIe trace in 2035, and a driver signed today with a 256-bit EC key is forgeable by any adversary holding the public key once Shor arrives. "Model weights in flight" is exactly the kind of secret whose confidentiality must survive the cryptographic transition — you cannot ship a 70B parameter model through an EC-protected channel and expect that secret to stay safe for the decade-plus lifetime of the deployment. This library is the PQC layer that belongs above the vendor's confidential-computing story, not below it: ML-KEM for key agreement, ML-DSA for driver integrity, AES-256 for the bulk data.

## Examples

* [`examples/basic_channel.py`](examples/basic_channel.py) — establish an ML-KEM channel and round-trip a tensor.
* [`examples/driver_attestation.py`](examples/driver_attestation.py) — sign a fake `nvidia.ko`, verify via allow-list, show the untrusted-signer reject path.
* [`examples/tensor_tamper_detection.py`](examples/tensor_tamper_detection.py) — flip a byte of ciphertext and watch AES-GCM detect it.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src/ tests/ examples/
```

## License

Apache 2.0. See [LICENSE](LICENSE).
