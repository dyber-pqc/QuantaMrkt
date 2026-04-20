# PQC Agent Wallet

![PQC Native](https://img.shields.io/badge/PQC-Native-blue)
![ML-KEM-768](https://img.shields.io/badge/ML--KEM--768-FIPS%20203-green)
![ML-DSA-65](https://img.shields.io/badge/ML--DSA--65-FIPS%20204-green)
![AES-256-GCM](https://img.shields.io/badge/AES--256--GCM-FIPS%20197-green)
![License](https://img.shields.io/badge/License-Apache%202.0-orange)
![Version](https://img.shields.io/badge/version-0.1.0-lightgrey)

**A quantum-resistant credential vault for AI agents.** Stop scattering API keys across `.env` files, `os.environ`, and LangChain memory. This library gives each AI agent a single encrypted `*.wallet` file, unlocked with a passphrase or an **ML-KEM-768** encapsulated key, with credentials encrypted at rest using **AES-256-GCM** and every access signed into a tamper-evident **ML-DSA** audit log. Drop-in integrations for LangChain, AutoGen, and CrewAI.

## The Problem

AI agents need credentials: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, database passwords, OAuth tokens, client certs. Today, those live in:

- **`.env` files** on developer laptops and production containers (plaintext on disk).
- **Classical secret managers** (Vault, AWS Secrets Manager) that protect data in transit with RSA/ECDSA - breakable by a sufficiently large quantum computer ("harvest now, decrypt later").
- **Agent memory** (LangChain `ChatOpenAI(api_key=...)`) - held in plaintext in process RAM, accessible to every tool the agent invokes.

If any of those stores is exfiltrated today and an adversary holds it until a CRQC (cryptographically relevant quantum computer) exists, every classical-crypto-protected secret is retroactively broken.

## The Solution

Each agent gets a local `*.wallet` file:

- Credentials encrypted with **AES-256-GCM** (FIPS 197 - symmetric, quantum-resistant at 128-bit Grover-adjusted security).
- Unlock key derived either from a passphrase via **PBKDF2-HMAC-SHA256** (600k iterations) or encapsulated to a recipient's **ML-KEM-768** public key (FIPS 203, NIST PQC).
- Wallet file signed with the owner's **ML-DSA-65** key (FIPS 204) - tamper-evident at rest.
- Every `get`, `put`, `delete`, `unlock` operation recorded as a signed entry in an append-only audit log.

## Installation

```bash
pip install pqc-agent-wallet
```

With LangChain helpers:

```bash
pip install "pqc-agent-wallet[langchain]"
```

Development:

```bash
pip install -e ".[dev]"
```

## Quick Start

```python
from quantumshield import AgentIdentity
from pqc_agent_wallet import Wallet

owner = AgentIdentity.create("my-agent")

# Create + populate
w = Wallet.create_with_passphrase("agent.wallet", "hunter2", owner)
w.put("openai_api_key", "sk-...", service="openai", tags=["prod"])
w.put("postgres_password", "db-pass", service="postgres", scheme="password")
w.save()
w.lock()

# Later (same process or another)...
w = Wallet.load("agent.wallet", owner)
w.unlock_with_passphrase("hunter2")
api_key = w.get("openai_api_key")
```

## Architecture

```
  Passphrase                 Wallet file (*.wallet)
  ----------                 ----------------------
       |                              |
       | PBKDF2-HMAC-SHA256           |
       |  (600k iterations)           |
       |                              |
       v                              v
  32-byte key ----+        +--> [ML-DSA-65 signature]
                  |        |        over canonical
                  |        |        payload bytes
                  v        |
          [AES-256-GCM] -->|
          per-credential   |
          (random nonce)   |
                           |
        +------------------+-----------------+
        |                                    |
        v                                    v
  encrypted_credentials           kdf / kem_encapsulation
  { name -> (nonce, ct, meta) }   (how to re-derive the key)
        |
        +--> sealed, authenticated (GCM tag) and individually decryptable

  Every get / put / delete / unlock -->  [ML-DSA-signed audit entry]
                                          (actor DID, ts, op, target)
```

For KEM-unlocked wallets, swap the passphrase branch for:

```
  Recipient ML-KEM-768 pubkey --> encapsulate() --> (ct, symmetric key)
                                                       |
                                                       v
                                                 same AES-256-GCM path
```

The recipient later runs `decapsulate(ct, their_priv_key)` to recover the symmetric key and unlock.

## Cryptography

| Layer | Primitive | Standard | Notes |
|---|---|---|---|
| Symmetric encryption | AES-256-GCM | FIPS 197 | 12-byte nonce, 16-byte GCM tag |
| Key derivation (passphrase mode) | PBKDF2-HMAC-SHA256 | RFC 8018 | 600,000 iterations (OWASP 2023) |
| Key encapsulation | ML-KEM-768 | FIPS 203 | Via QuantumShield; stub path for dev |
| Signatures (wallet + audit) | ML-DSA-65 | FIPS 204 | Via QuantumShield; Ed25519 fallback |
| Hashing | SHA3-256 | FIPS 202 | For canonical digests before signing |

AES-256-GCM is already considered quantum-resistant: Grover's algorithm halves the effective security of symmetric ciphers, so AES-256 provides ~128-bit post-quantum security - still well above the practical attack floor.

## Threat Model

| Threat | Mitigation |
|---|---|
| **Quantum decryption of stored secrets** ("harvest now, decrypt later") | Symmetric key never travels over a classical asymmetric channel; only ever PBKDF2-derived or ML-KEM-encapsulated. |
| **Wallet file tampering** (attacker edits encrypted payload) | ML-DSA signature over the entire canonical payload is re-verified on every load; any mutation fails verification. |
| **Wrong passphrase accepted** | Unlock tries to decrypt a stored credential; GCM tag failure surfaces as `InvalidPassphraseError`. |
| **Credential leak via logs** | `Credential.to_safe_dict()` redacts the value. Audit log stores only the credential name, not its value. |
| **Unauthorized access by another agent** | Agents have separate wallets. Per-agent DID embedded in audit entries. |
| **Stale credential abuse** | `rotate()` updates the stored value and `rotated_at` timestamp; downstream policy can reject credentials with stale `rotated_at`. |
| **Offline attacker with a GPU farm** | PBKDF2 at 600k iterations makes brute force expensive; KEM mode removes passphrase brute force entirely. |

## Integrations

### LangChain (or any "callable that returns a secret" pattern)

```python
from pqc_agent_wallet.integrations import make_langchain_secret_provider

provider = make_langchain_secret_provider(wallet)
# provider("openai_api_key") -> "sk-..."

# Or bulk-resolve env-style mapping:
from pqc_agent_wallet.integrations import walletize_env
env = walletize_env(wallet, {"OPENAI_API_KEY": "openai_api_key"})
```

### AutoGen / CrewAI / anything that reads `os.getenv`

```python
from pqc_agent_wallet.integrations import install_env_shim
install_env_shim(wallet)

# Legacy code that does os.getenv("OPENAI_API_KEY") now transparently
# falls back to wallet.get("openai_api_key") when the env var is unset.
```

### Per-agent isolation (CrewAI pattern)

```python
# Give every agent its own wallet; one agent's compromise doesn't leak others.
researcher_wallet = Wallet.load("researcher.wallet", researcher_identity)
writer_wallet = Wallet.load("writer.wallet", writer_identity)
```

## API Reference

### `Wallet`

| Method | Description |
|---|---|
| `Wallet.create_with_passphrase(path, passphrase, owner)` | New wallet unlocked via PBKDF2(passphrase). |
| `Wallet.create_with_kem(path, recipient_pubkey, alg, owner)` | New wallet unlocked via ML-KEM decapsulation. |
| `Wallet.load(path, owner)` | Load + verify ML-DSA signature. |
| `unlock_with_passphrase(p)` | Derive and validate the unlock key. |
| `unlock_with_kem_private_key(sk, alg)` | Decapsulate the stored ciphertext. |
| `lock()` | Zero the in-memory key. |
| `put(name, value, service=, description=, scheme=, tags=, expires_at=)` | Add or overwrite a credential. |
| `get(name) -> str` | Retrieve plaintext (unlocked only). |
| `get_credential(name) -> Credential` | Full Credential with metadata. |
| `delete(name)` | Remove a credential. |
| `rotate(name, new_value)` | Overwrite value, preserve created_at, update rotated_at. |
| `list_names() -> list[str]` | Sorted names. |
| `list_metadata() -> list[CredentialMetadata]` | All metadata. |
| `save()` | Sign payload with owner key, write file. |
| `audit` | `WalletAuditLog` instance. |
| `is_unlocked` | Bool property. |

### `Credential` / `CredentialMetadata`

Dataclasses. `CredentialMetadata` fields: `name`, `scheme`, `service`, `description`, `created_at`, `rotated_at`, `expires_at`, `tags`. `Credential.to_safe_dict()` redacts the `value` for logging.

### `WalletAuditLog` + `WalletAuditEntry`

Append-only log with ML-DSA-signed entries. Fields on each entry: `timestamp`, `operation`, `actor_did`, `credential_name`, `success`, `details`, `signer_did`, `algorithm`, `signature`. `log.entries(limit=, operation=, credential_name=)` returns the most recent matching entries. `entry.verify_signature(public_key_hex)` validates the ML-DSA signature.

### Exceptions

| Exception | When |
|---|---|
| `WalletError` | Base class. |
| `WalletLockedError` | Operation requires unlocked wallet. |
| `CredentialNotFoundError` | Name not present. |
| `InvalidPassphraseError` | Passphrase failed GCM auth check. |
| `TamperedWalletError` | Wallet file signature failed verification. |
| `WalletFormatError` | Malformed or wrong-version wallet file. |

## Examples

See the `examples/` directory:

- **`basic_usage.py`** - create, save, reload, read, audit.
- **`langchain_integration.py`** - `make_langchain_secret_provider` + `walletize_env`.
- **`env_shim_demo.py`** - transparent `os.getenv` fallback to the wallet.

Run them:

```bash
python examples/basic_usage.py
python examples/langchain_integration.py
python examples/env_shim_demo.py
```

## Why PQC Matters For Credentials

Credential-protection systems typically rotate on multi-year cadences (annual key rotation is considered aggressive). A credential you encrypt with RSA-2048 today will be sitting on someone's disk - or in a backup bucket, or on a compromised laptop - for the entire decade-long runway to practical cryptanalytic quantum computers. ML-KEM and ML-DSA close that window now, so you never have to re-encrypt the whole corpus in a panic later. Symmetric AES-256-GCM remains safe with classical assumptions; the post-quantum concern is exclusively about how the symmetric key gets to the machine, which is exactly what ML-KEM protects.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src/ tests/ examples/
```

## Related

Part of the [QuantaMrkt](https://quantamrkt.com) post-quantum tooling registry. See also:

- **QuantumShield** - the underlying PQC toolkit (`AgentIdentity`, ML-DSA / ML-KEM primitives).
- **PQC RAG Signing** - sister tool for sealing RAG pipeline chunks with ML-DSA.
- **PQC MCP Transport** - sister tool for signing Model Context Protocol JSON-RPC messages.

## License

Apache License 2.0. See [LICENSE](LICENSE).
