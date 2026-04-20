# PQC KV Cache Encryption

![PQC Native](https://img.shields.io/badge/PQC-Native-blue)
![ML-KEM-768](https://img.shields.io/badge/ML--KEM--768-FIPS%20203-green)
![AES-256-GCM](https://img.shields.io/badge/AES--256--GCM-NIST%20SP%20800--38D-teal)
![License](https://img.shields.io/badge/License-Apache%202.0-orange)
![Version](https://img.shields.io/badge/version-0.1.0-lightgrey)

**Per-tenant, quantum-safe encryption for the LLM KV cache.** Multi-tenant inference servers store gigabytes of KV cache in shared host/device RAM. A side-channel or a compromised co-tenant can lift another user's private conversation state directly out of that cache. This library wraps every KV cache entry in a fresh **AES-256-GCM** envelope whose key is derived per session via **ML-KEM-768**, enforces strict tenant isolation at the cryptographic boundary, rotates keys on a configurable policy, and ships with an append-only audit log for every encrypt / decrypt / rotate / isolation-violation event.

## The Problem

Long-context LLM inference keeps past token activations in the **KV cache** - a per-layer, per-position tensor store that can run to multiple GB. On a multi-tenant inference server (vLLM, TGI, or any production stack sharing a GPU across requests) that cache sits in plaintext process memory:

- **Side-channel reads.** A malicious co-tenant with timing or page-table-based primitives can read another tenant's cache pages.
- **Cross-request leakage.** A bug in cache eviction or session routing can hand one tenant's intermediate state to another.
- **Harvest-now-decrypt-later.** Even if host-level encryption is on, classical key exchange (ECDH) recorded today is broken by a future CRQC.
- **Regulated workloads.** Healthcare, finance, and legal inference pipelines have 7+ year retention requirements on conversation state; classical confidentiality alone no longer clears the audit bar.

## The Solution

- **ML-KEM-768** derives a fresh 32-byte symmetric key per `TenantSession`. In production the tenant presents a KEM public key and the inference server runs Encapsulate; here we delegate to [`quantumshield`](https://github.com/dyber-pqc/quantumshield).
- **AES-256-GCM** encrypts every `KVCacheEntry`. One nonce per entry, AAD binds `EntryMetadata` + `sequence_number` + `key_len` so tampering with layer/position/sequence surfaces as a `DecryptionError`.
- **`TenantIsolationManager`** holds a session per tenant and refuses cross-tenant decrypts even when asked explicitly; a misrouted ciphertext raises `TenantIsolationError` before AES touches the bytes.
- **`KeyRotationPolicy`** rotates the per-session key after N entries or T seconds, resetting the sequence counter.
- **`KVAuditLog`** is append-only and records `encrypt`, `decrypt`, `rotate`, and `isolation-violation` events.

## Installation

```bash
pip install pqc-kv-cache-encryption
```

Development:

```bash
pip install -e ".[dev]"
```

## Quick Start

```python
import os

from pqc_kv_cache import (
    CacheDecryptor,
    CacheEncryptor,
    EntryMetadata,
    KVCacheEntry,
    TenantIdentity,
    establish_tenant_session,
)

# 1. Establish a per-tenant session (ML-KEM-768 derived AES-256-GCM key).
tenant = TenantIdentity(tenant_id="tenant-alice", display_name="Alice Corp")
session = establish_tenant_session(tenant)

# 2. Wrap a KV cache entry in a signed envelope.
meta = EntryMetadata(
    tenant_id=tenant.tenant_id,
    session_id=session.session_id,
    layer_idx=0,
    position=12,
    token_id=2048,
)
entry = KVCacheEntry(
    metadata=meta,
    key_tensor_bytes=os.urandom(64),   # raw bytes of K vector
    value_tensor_bytes=os.urandom(64), # raw bytes of V vector
)
enc = CacheEncryptor(session).encrypt_entry(entry)

# 3. Decrypt with the same session. AES-GCM verifies AAD, tenant, replay.
decrypted = CacheDecryptor(session).decrypt_entry(enc)
assert decrypted.key_tensor_bytes == entry.key_tensor_bytes
```

Multi-tenant with strict isolation:

```python
from pqc_kv_cache import TenantIsolationManager, TenantIsolationError

mgr = TenantIsolationManager()
mgr.create_session(TenantIdentity(tenant_id="tenant-alice"))
mgr.create_session(TenantIdentity(tenant_id="tenant-bob"))

alice_enc = mgr.encrypt("tenant-alice", alice_entry)

# Bob can NEVER decrypt Alice's entry, even when using his own valid session.
try:
    mgr.decrypt("tenant-bob", alice_enc)
except TenantIsolationError:
    print("blocked at the isolation boundary")
```

## Architecture

```
+-----------------------------+              +-----------------------------+
|  Tenant Alice               |              |  Tenant Bob                 |
|  (client)                   |              |  (client)                   |
+--------------+--------------+              +--------------+--------------+
               |                                             |
               |  ML-KEM-768 handshake (per session)         |
               v                                             v
+---------------------------------------------------------------------------+
|                   Inference Server (multi-tenant)                         |
|                                                                           |
|  TenantIsolationManager                                                   |
|    +------------------------+        +------------------------+           |
|    | TenantSession (alice)  |        | TenantSession (bob)    |           |
|    |   symmetric_key (32B)  |        |   symmetric_key (32B)  |           |
|    |   next_sequence        |        |   next_sequence        |           |
|    |   entries_encrypted    |        |   entries_encrypted    |           |
|    +----------+-------------+        +----------+-------------+           |
|               |                                 |                         |
|               v                                 v                         |
|    CacheEncryptor / CacheDecryptor   CacheEncryptor / CacheDecryptor      |
|       AES-256-GCM + AAD                 AES-256-GCM + AAD                 |
|       + tenant-id enforcement           + tenant-id enforcement           |
|               |                                 |                         |
|               v                                 v                         |
|    +---------------------+        +---------------------+                 |
|    | EncryptedEntry      |        | EncryptedEntry      |                 |
|    |  (alice ciphertext) |        |  (bob ciphertext)   |                 |
|    +---------+-----------+        +---------+-----------+                 |
|              |                              |                             |
|              +-----------+------------------+                             |
|                          v                                                |
|             +---------------------------+                                 |
|             |  KV cache in GPU/host RAM |  (only ciphertext lives here)   |
|             +---------------------------+                                 |
|                                                                           |
|  KeyRotationPolicy  -- rotates session keys on entry count / age          |
|  KVAuditLog         -- encrypt / decrypt / rotate / isolation-violation   |
+---------------------------------------------------------------------------+
```

## Cryptography

| Primitive                  | Purpose                                                     | Algorithm     |
| -------------------------- | ----------------------------------------------------------- | ------------- |
| Per-session key            | Fresh 32-byte symmetric key per tenant session              | ML-KEM-768    |
| Per-entry encryption       | Confidentiality + integrity of K/V tensor bytes             | AES-256-GCM   |
| AAD binding                | `EntryMetadata` + `sequence_number` + `key_len` -> tag      | AES-GCM tag   |
| Session-key derivation     | SHA3-256 over KEM keypair bytes (production: Decapsulate)   | SHA3-256      |

Signing and KEM keys are delegated to [`quantumshield`](https://github.com/dyber-pqc/quantumshield), which prefers real `liboqs` ML-KEM / ML-DSA when available and falls back to a transitional backend otherwise.

## Threat Model

| Adversary capability                                            | Coverage                                                                      |
| --------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Read KV cache pages for another tenant                          | All entries are AES-256-GCM encrypted; attacker sees only ciphertext.         |
| Replay a previously captured `EncryptedEntry`                   | `CacheDecryptor` tracks seen nonces and raises `NonceReplayError`.            |
| Tamper with `EntryMetadata` (layer_idx, position, tenant_id)    | AAD binding -> AES-GCM tag fails -> `DecryptionError`.                        |
| Submit another tenant's ciphertext through a valid session      | `TenantIsolationError` raised before AES touches bytes.                       |
| Long-lived session key exposure                                 | `KeyRotationPolicy` rotates on entry-count / age; sequence counter resets.    |
| Session outlives its TTL                                        | `SessionExpiredError` on every encrypt/decrypt after `expires_at`.            |
| Harvest-now-decrypt-later on the KEM handshake                  | ML-KEM-768 provides IND-CCA2 security under quantum adversaries.              |
| Orphaned tenant state after disconnect                          | `close_session()` drops the session and its key from memory.                  |

## Performance Considerations

This library is written in pure Python and is intended as the **cryptographic envelope** for multi-tenant LLM inference, not a hot-path encryption kernel. Production deployments wrap the same patterns in:

- A CUDA / ROCm kernel that operates on the K/V tensors in device memory.
- A driver-side AES-GCM engine (H100 confidential compute, AMD SEV-SNP).
- A batched nonce / sequence allocator to amortize session bookkeeping across a batch of requests.

The envelope formats (`EncryptedEntry`, AAD shape, `TenantSession` state machine) are deliberately portable so that the native kernel and the Python reference implementation produce interoperable ciphertexts.

## API Reference

### `TenantIdentity`
`tenant_id: str`, `display_name: str = ""` — frozen dataclass identifying a tenant.

### `establish_tenant_session(tenant, algorithm=KEMAlgorithm.ML_KEM_768, ttl_seconds=900) -> TenantSession`
Derive a fresh 32-byte symmetric key for `tenant` via ML-KEM-768 and return a `TenantSession`.

### `TenantSession`
Holds `symmetric_key`, `next_sequence`, `entries_encrypted`, `created_at`, `expires_at`. Methods: `is_valid()`, `check_valid()`, `consume_sequence()`, `rotate_key(new_key)`, `to_public_dict()`.

### `KVCacheEntry` / `EncryptedEntry` / `EntryMetadata`
`KVCacheEntry` holds `metadata`, `key_tensor_bytes`, `value_tensor_bytes`. `EncryptedEntry` holds `metadata`, `nonce` (hex), `ciphertext` (hex), `key_len`, `sequence_number`. `EntryMetadata` is frozen and carries `tenant_id`, `session_id`, `layer_idx`, `position`, `token_id`, `kv_role`.

### `CacheEncryptor(session)` / `CacheDecryptor(session)`
`encrypt_entry(KVCacheEntry) -> EncryptedEntry` and `decrypt_entry(EncryptedEntry) -> KVCacheEntry`. Both enforce tenant-id match. Decryptor tracks nonces for replay protection.

### `KeyRotationPolicy(max_entries=100_000, max_age_seconds=300)`
`should_rotate(session) -> (bool, RotationTrigger | None)` and `rotate(session) -> bytes` (new 32-byte key). `RotationTrigger` is `ENTRY_COUNT`, `TIME_ELAPSED`, or `MANUAL`.

### `TenantIsolationManager`
`create_session(tenant)`, `get_session(tenant_id)`, `encrypt(tenant_id, entry)`, `decrypt(tenant_id, enc)`, `close_session(tenant_id)`, `list_active_tenants()`.

### `KVAuditLog` / `KVAuditEntry`
`log_encrypt(...)`, `log_decrypt(...)`, `log_rotate(...)`, `log_isolation_violation(...)`, `entries(limit, tenant_id, operation)`, `export_json()`.

### Errors
All under `KVCacheError`: `TenantIsolationError`, `SessionExpiredError`, `DecryptionError`, `NonceReplayError`, `KeyRotationRequiredError`, `UnknownTenantError`.

## Why PQC Matters for the KV Cache

Inference logs and intermediate conversation state are retained for 7+ years in regulated industries:

- **Healthcare (HIPAA):** 6-year minimum retention on any PHI-bearing record, including the model context that reasoned over it.
- **Finance (SEC 17a-4, MiFID II):** 5-7 year retention on all communications with a client, including AI-assisted drafting.
- **Legal (privilege / e-discovery):** communications privilege only survives if the confidentiality chain is intact.

The same adversary who is recording your classical TLS session today - harvest-now-decrypt-later - is also recording the residual state of your inference servers. A PQC envelope around the KV cache is what keeps that state confidential past the arrival of a cryptographically relevant quantum computer.

## Examples

- `examples/basic_kv_encryption.py` - single tenant, encrypt/decrypt 3 entries, inspect audit log.
- `examples/multi_tenant_isolation.py` - Alice and Bob co-resident, cross-tenant decrypt is rejected.
- `examples/key_rotation.py` - `KeyRotationPolicy` with `max_entries=5`, observe rotation mid-stream.

## License

Apache License 2.0 - see `LICENSE`.
