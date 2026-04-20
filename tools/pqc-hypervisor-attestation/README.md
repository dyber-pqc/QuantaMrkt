# PQC Hypervisor Attestation

![PQC Native](https://img.shields.io/badge/PQC-Native-blue)
![ML-DSA-65](https://img.shields.io/badge/ML--DSA--65-FIPS%20204-green)
![Backends](https://img.shields.io/badge/backends-SEV--SNP%20%7C%20TDX%20ready-purple)
![License](https://img.shields.io/badge/License-Apache%202.0-orange)
![Version](https://img.shields.io/badge/version-0.1.0-lightgrey)

**Sigstore for hypervisor memory attestation.** When an AI workload runs inside a cloud VM, the hypervisor (KVM, QEMU, Hyper-V) is transparent: nothing cryptographically proves to the tenant that model weights in RAM have not been read or rewritten by a malicious host. This library is the **post-quantum cryptographic envelope** — `MemoryRegion`, `AttestationClaim`, `AttestationReport`, ML-DSA-signed, independently verifiable — that a hypervisor project, TEE runtime, or confidential-computing framework can plug its memory-reading primitives into. The library ships pluggable backends for **AMD SEV-SNP** and **Intel TDX** as stubs, plus a reference `InMemoryBackend` for tests.

## The Problem

Cloud AI inference workloads place multi-hundred-megabyte model weights in guest memory. The hypervisor can read or rewrite every page. Today's tenants rely on contractual trust ("the cloud provider said they wouldn't") plus coarse platform-level attestation (MRTD, launch digest) that only covers VM boot — not the *runtime* state of the pages you actually care about. An attacker with host compromise, or a curious operator, can:

- Silently exfiltrate proprietary model weights.
- Swap in backdoored weights for a single request.
- Corrupt the KV cache to influence in-flight generations.

None of this is visible to the guest without a runtime memory attestation protocol. And any attestation that signs memory state with RSA or ECDSA today is retroactively forgeable once a CRQC exists — which is why the cryptographic envelope must be post-quantum from day one.

## The Solution

Every attestation is a post-quantum signed, freshness-bounded claim about specific memory regions:

- **SHA3-256** per-region content hashes — deterministic snapshot of what lives at those pages.
- **ML-DSA (FIPS 204)** signature over the canonical report bytes, by a known attester DID.
- **Expiry and nonce** for replay resistance.
- **Expected-hash pinning** so a remote verifier can detect drift from trusted state.
- **Pluggable backends** — the library never reads memory itself; backends do, using `/dev/sev-guest`, `/dev/tdx-guest`, or whatever primitive the real TEE exposes.

## Installation

```bash
pip install pqc-hypervisor-attestation
```

Development:

```bash
pip install -e ".[dev]"
```

## Quick Start

```python
from quantumshield.identity.agent import AgentIdentity

from pqc_hypervisor_attestation import (
    AttestationVerifier,
    Attester,
    ContinuousAttester,
    InMemoryBackend,
    MemoryRegion,
    RegionSnapshot,
)

# 1. Identity + signer.
identity = AgentIdentity.create("llama-host-attester", capabilities=["attest"])
attester = Attester(identity)

# 2. Backend with a pinned region.
backend = InMemoryBackend()
weights = MemoryRegion(
    region_id="model-weights-0",
    description="Llama weight shard 0",
    address=0x1000,
    size=128,
    protection="RO",
)
content = b"\xaa" * 128
backend.register("model-serving-1", weights, content)

# 3. Continuous attester with pinned expected hash.
loop = ContinuousAttester(
    attester=attester,
    backend=backend,
    workload_id="model-serving-1",
    expected_hashes={weights.region_id: RegionSnapshot.hash_bytes(content)},
)

report = loop.attest_once()
result = AttestationVerifier.verify(report, strict=True)
assert result.valid
```

## Architecture

```
+-----------------------------+       +------------------------------+
|   AI workload (guest VM)    |       |  Remote verifier             |
|                             |       |                              |
|  ContinuousAttester         |       |  AttestationVerifier         |
|   |                         |       |   |                          |
|   v                         |       |   v                          |
|  AttestationBackend         |       |  - ML-DSA signature check    |
|   (SEV-SNP | TDX | memory)  |       |  - expiry check              |
|   |                         |       |  - expected_hash pinning     |
|   v                         |       |                              |
|  MemoryRegion ---> RegionSnapshot -> AttestationClaim              |
|                                     |                              |
|                                     v                              |
|                              AttestationReport (bundle)            |
|                                     |                              |
|                                     v                              |
|                              ML-DSA sign (quantumshield)           |
+-----------------------------+       +------------------------------+
               |                                 ^
               |      signed AttestationReport   |
               +---------------------------------+
```

## Cryptography

| Primitive                 | Purpose                                  | Algorithm     |
| ------------------------- | ---------------------------------------- | ------------- |
| Region content hash       | Fingerprint memory bytes                 | SHA3-256      |
| Report canonical digest   | Input to signer                          | SHA3-256      |
| Attestation signature     | Bind report to attester DID              | ML-DSA-65     |
| Verifier trust anchor     | Attester public key (from DID / keystore)| ML-DSA public |

All signing is delegated to [`quantumshield`](https://github.com/dyber-pqc/quantumshield), which prefers real `liboqs` ML-DSA when available and falls back to transitional Ed25519.

## Threat Model

| Adversary capability                              | Coverage                                                         |
| ------------------------------------------------- | ---------------------------------------------------------------- |
| Forges an attestation report from scratch         | Blocked — requires the attester's ML-DSA private key.            |
| Replays an old valid report to hide drift         | Blocked — `expires_at` bound + per-report nonce in each claim.   |
| Rewrites model weights in guest memory            | Detected — region snapshot hash diverges from `expected_hash`.   |
| Substitutes a newer signed report from same key   | Mitigated — verifier pins expected hashes independently.         |
| Tampers with report fields in transit             | Blocked — canonical-bytes + ML-DSA binds every field.            |
| Q-day adversary with CRQC                         | Out of scope for ECDSA/RSA signers; covered here by ML-DSA.      |
| Compromises the attester key via guest escape     | Out of scope — mitigate with SEV-SNP / TDX sealed key storage.   |

## Backend Integration Guide

The library defines a single abstract interface:

```python
class AttestationBackend(ABC):
    name: str
    platform: str

    def list_regions(self, workload_id: str) -> list[MemoryRegion]: ...
    def snapshot(self, region: MemoryRegion) -> RegionSnapshot: ...
```

Any backend that can enumerate memory ranges and hash their bytes can plug in.

### AMD SEV-SNP (`/dev/sev-guest`)

The shipped `AMDSEVSNPBackend` is a stub that documents the expected behaviour. A real integration:

1. Reads the SEV-SNP launch digest at VM start and stores per-region base/size in its workload manifest.
2. For `list_regions`, returns `MemoryRegion` entries whose `address` is the guest-physical base and `size` is the range length.
3. For `snapshot`, issues the `SNP_GET_REPORT` ioctl on `/dev/sev-guest`, reads the backing pages into a buffer, and returns `RegionSnapshot.create(region_id, buffer)`.

### Intel TDX (`/dev/tdx-guest`)

`IntelTDXBackend` follows the same pattern using `TDX_CMD_GET_REPORT0` and the TD's MRTD / RTMR measurements.

### Your own backend

Subclass `AttestationBackend`, implement `list_regions` and `snapshot`, and pass an instance to `ContinuousAttester`. The library handles canonicalisation, signing, and verification uniformly.

## API Reference

### Data types

| Class              | Description                                                       |
| ------------------ | ----------------------------------------------------------------- |
| `MemoryRegion`     | Addressable range `(region_id, address, size, protection)`.       |
| `RegionSnapshot`   | `(region_id, content_hash, size, taken_at)` SHA3-256 fingerprint. |
| `AttestationClaim` | One signed statement about one region at one point in time.       |
| `AttestationReport`| Bundle of claims + ML-DSA envelope + expiry.                      |
| `VerificationResult`| Breakdown of signature / expiry / drift checks.                  |

### Signers and verifiers

| Symbol                   | Purpose                                                     |
| ------------------------ | ----------------------------------------------------------- |
| `Attester`               | Wraps an `AgentIdentity`; signs reports.                    |
| `AttestationVerifier`    | Static verifier; returns `VerificationResult`.              |
| `AttestationVerifier.verify_or_raise` | Raises `RegionDriftError` / `AttestationVerificationError`. |
| `ContinuousAttester`     | Periodic loop: enumerate regions, snapshot, sign.           |

### Backends

| Class              | Use                                                       |
| ------------------ | --------------------------------------------------------- |
| `InMemoryBackend`  | Reference / tests / tutorials.                            |
| `AMDSEVSNPBackend` | Stub for AMD SEV-SNP (plug into `/dev/sev-guest`).        |
| `IntelTDXBackend`  | Stub for Intel TDX (plug into `/dev/tdx-guest`).          |

### Exceptions

`HypervisorAttestationError` -> `InvalidRegionError`, `AttestationVerificationError` (-> `RegionDriftError`), `BackendError` (-> `UnknownBackendError`).

## Why PQC Matters for Hypervisor Attestation

Cloud confidential-computing deployments live for a decade or more. A VM image spun up in 2026 may still be attested by the same kind of signature in 2036 — long enough for a CRQC to exist. An attestation signed today with ECDSA or RSA can be **retroactively forged** by any adversary holding a recording of the public key and the signed payload: in 2035 they can manufacture a fresh, valid-looking "clean" attestation for a workload they actually tampered with in 2026, and no auditor can distinguish it from a real one. Post-quantum signatures break that chain: even with Shor's algorithm, ML-DSA remains unbroken, so historical attestations continue to bind the host to its claim. Hypervisor attestation is exactly the place that non-repudiation must survive the cryptographic transition.

## Examples

* [`examples/basic_attestation.py`](examples/basic_attestation.py) — end-to-end sign-and-verify over two in-memory regions.
* [`examples/detect_memory_tampering.py`](examples/detect_memory_tampering.py) — mutate a region between attestations and watch drift surface.
* [`examples/continuous_loop_demo.py`](examples/continuous_loop_demo.py) — run the periodic attestation loop and stream reports.

## License

Apache 2.0. See [LICENSE](LICENSE).
