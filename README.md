<p align="center">
  <img src="https://img.shields.io/badge/PQC-Native-00d4ff?style=for-the-badge" alt="PQC Native" />
  <img src="https://img.shields.io/badge/ML--DSA--87-Signing-00ff88?style=for-the-badge" alt="ML-DSA-87" />
  <img src="https://img.shields.io/badge/CNSA_2.0-Ready-blueviolet?style=for-the-badge" alt="CNSA 2.0 Ready" />
  <img src="https://img.shields.io/pypi/v/quantumshield?style=for-the-badge&color=00d4ff" alt="PyPI" />
  <img src="https://img.shields.io/github/actions/workflow/status/dyber-pqc/QuantaMrkt/ci.yml?style=for-the-badge&label=CI" alt="CI" />
  <img src="https://img.shields.io/github/license/dyber-pqc/QuantaMrkt?style=for-the-badge" alt="License" />
</p>

<h1 align="center">QuantaMrkt</h1>

<p align="center">
  <strong>The Quantum-Safe AI Marketplace</strong><br/>
  PQC-native model signing, agent identity, and HNDL risk assessment for the AI ecosystem.
</p>

<p align="center">
  <a href="https://quantamrkt.com">Website</a> &bull;
  <a href="https://quantamrkt.com/models">Model Hub</a> &bull;
  <a href="https://quantamrkt.com/download">Download CLI</a> &bull;
  <a href="https://quantamrkt.com/docs">Docs</a> &bull;
  <a href="https://quantamrkt.com/transparency">Transparency Log</a>
</p>

---

## What is QuantaMrkt?

QuantaMrkt is the **trust layer for AI in the post-quantum era**. We provide cryptographic verification for AI models and agents using post-quantum cryptography (PQC) — specifically ML-DSA (FIPS 204) and ML-KEM (FIPS 203) — so that model integrity and provenance remain verifiable even after quantum computers can break RSA and ECDSA.

**The problem:** AI model weights worth billions are protected by classical cryptography that quantum computers will break. Nation-state adversaries are already harvesting encrypted data today ([Harvest Now, Decrypt Later](https://en.wikipedia.org/wiki/Harvest_now,_decrypt_later)). Every model signed with RSA or ECDSA will have forgeable signatures when cryptographically relevant quantum computers arrive (est. 2030-2035). CNSA 2.0 mandates PQC adoption by January 2027.

**Our solution:** QuantaMrkt provides PQC-native signing, verification, and risk assessment — not as a migration layer on top of classical crypto, but as a ground-up quantum-safe system.

### How it works

```
Developer                    QuantaMrkt                     Consumer
   │                            │                              │
   │  quantumshield push        │                              │
   │  (hash files + ML-DSA      │                              │
   │   sign + upload manifest)  │                              │
   │ ──────────────────────────>│                              │
   │                            │  Store in D1 + R2            │
   │                            │  Append to transparency log  │
   │                            │  Compute HNDL risk score     │
   │                            │                              │
   │                            │<──────────────────────────── │
   │                            │  quantumshield verify        │
   │                            │  (fetch manifest + verify    │
   │                            │   ML-DSA signatures locally) │
   │                            │                              │
   │                            │  ✓ Signatures valid          │
   │                            │  ✓ File hashes match source  │
   │                            │  ✓ Chain of trust verified   │
```

## Products

### PQ-AID — Post-Quantum Agent Identity

Cryptographic identity for AI agents using ML-DSA-65/87 signing keys and W3C DID-compatible identifiers.

- **ML-DSA key pairs** — FIPS 204 digital signatures for agent authentication
- **DID identifiers** — `did:pqaid:...` format for cross-platform interoperability
- **Delegation chains** — Scoped, time-limited permission delegation between agents
- **Encrypted channels** — ML-KEM-768 key encapsulation for agent-to-agent messaging

### Shield Registry — HNDL-Resistant Model Protection

PQC-signed model manifests with SHA3-256 file hashes and HNDL risk scoring.

- **Model manifests** — SHA3-256 hash of every file, signed with ML-DSA-87
- **HNDL risk calculator** — Quantified risk scoring based on model sensitivity and quantum timeline
- **Transparency log** — Append-only, hash-chained audit log of all registry operations
- **Multi-party verification** — Support for creator, auditor, and registry co-signatures

### Migrator — AI-Powered PQC Migration

Automated detection and replacement of quantum-vulnerable cryptography in codebases.

- **Multi-language analysis** — Python, TypeScript, Go, Rust, Java, C/C++
- **50+ vulnerability patterns** — RSA, ECDSA, ECDH, AES-CBC, SHA-1, and more
- **Automated code generation** — AI-generated migration code with KAT validation
- **CI/CD integration** — GitHub Actions workflow for continuous compliance monitoring

## Quick Start

### Install the CLI

```bash
# macOS / Linux
curl -fsSL https://quantamrkt.com/install.sh | sh

# Windows (PowerShell)
irm https://quantamrkt.com/install.ps1 | iex

# Or via pip
pip install quantumshield

# With real PQC crypto (ML-DSA via liboqs)
pip install quantumshield[pqc]
```

### Sign and push a model

```bash
# Authenticate with GitHub
quantumshield login

# Create a PQC signing identity
quantumshield agent create my-signer --set-default

# Hash files, sign with ML-DSA, push to registry
quantumshield push ./my-model --name myorg/my-model

# Verify a model's signatures
quantumshield verify meta-llama/Llama-3.1-8B-Instruct

# Search the registry
quantumshield search "llama 8b"
```

### Use as a Python library

```python
from quantumshield import AgentIdentity, ModelManifest

# Create a quantum-safe agent identity
agent = AgentIdentity.create("my-agent", capabilities=["sign:models"])

# Sign a model
manifest = ModelManifest.from_model("./my-model/")
manifest.sign(agent.signing_keypair)
manifest.save("./my-model/quantmrkt-manifest.json")

# Calculate HNDL risk
from quantumshield.registry.hndl import calculate_hndl_risk
risk = calculate_hndl_risk(
    artifact_type="fine_tuned_model",
    shelf_life_years=10,
    sensitivity="confidential",
    current_encryption="AES-256-GCM"
)
print(f"Risk: {risk['risk_level']} ({risk['risk_score']}/100)")
```

## Architecture

```
quantmrkt/
├── site/                    # Public website & dashboard
│   ├── src/pages/           # Astro SSR pages
│   │   ├── models/          # Public model hub (/models)
│   │   ├── agents/          # Agent directory (/agents)
│   │   ├── dashboard/       # Authenticated dashboard
│   │   ├── api/             # Cloudflare Worker API routes
│   │   └── transparency.astro
│   ├── src/lib/
│   │   ├── db.ts            # D1 database helpers
│   │   ├── auth.ts          # GitHub OAuth + HMAC sessions
│   │   └── transparency.ts  # Hash-chained audit log
│   ├── schema.sql           # D1 database schema
│   └── wrangler.toml        # Cloudflare Workers config
│
├── lib/                     # QuantumShield Python library
│   ├── src/quantumshield/
│   │   ├── core/            # ML-DSA/ML-KEM via liboqs
│   │   ├── identity/        # PQ-AID agent identity
│   │   ├── registry/        # Model signing & HNDL
│   │   ├── migrator/        # PQC migration engine
│   │   └── cli/             # Ollama-style CLI
│   └── tests/
│
├── api/                     # FastAPI backend (reference)
│   ├── src/quantmrkt_api/
│   │   ├── routes/          # REST API endpoints
│   │   ├── models/          # Pydantic schemas
│   │   └── services/        # Business logic
│   └── tests/
│
└── .github/workflows/
    ├── ci.yml               # Lint, test, build
    ├── deploy-site.yml      # Deploy to Cloudflare Workers
    ├── publish-lib.yml      # Publish to PyPI
    └── build-cli.yml        # PyInstaller binaries
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| **Website** | [Astro](https://astro.build) + [Tailwind CSS](https://tailwindcss.com) (SSR) |
| **Hosting** | [Cloudflare Workers](https://workers.cloudflare.com) |
| **Database** | [Cloudflare D1](https://developers.cloudflare.com/d1/) (SQLite at the edge) |
| **Object Storage** | [Cloudflare R2](https://developers.cloudflare.com/r2/) (model manifests) |
| **PQC Library** | Python + [liboqs](https://github.com/open-quantum-safe/liboqs) (ML-DSA, ML-KEM) |
| **CLI** | [Click](https://click.palletsprojects.com) + [Rich](https://rich.readthedocs.io) + [httpx](https://www.python-httpx.org) |
| **Auth** | GitHub OAuth + HMAC-SHA256 sessions |
| **CI/CD** | GitHub Actions |

## API

The QuantaMrkt API is served from Cloudflare Workers at `https://quantamrkt.com/api/`.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/models` | GET | List models (search, filter, sort, paginate) |
| `/api/models` | POST | Create a model (auth required) |
| `/api/models/{slug}` | GET | Model detail with files, signatures, HNDL |
| `/api/models/{slug}/versions` | POST | Push a new signed version (auth required) |
| `/api/models/{slug}/verify` | GET | Verify model signatures |
| `/api/agents` | GET | List registered agents |
| `/api/agents` | POST | Register an agent (auth required) |
| `/api/agents/{id}` | GET | Agent detail |
| `/api/users/me` | GET | Current user profile + stats (auth required) |
| `/api/transparency/log` | GET | Public transparency log |
| `/api/transparency/verify` | GET | Verify chain integrity |
| `/api/explore/trending` | GET | Trending models |
| `/api/explore/recent` | GET | Recent verifications |

Authentication uses either a session cookie (browser) or `Authorization: Bearer <github-token>` header (CLI).

## Cryptographic Algorithms

| Algorithm | Standard | Usage | Security Level |
|-----------|----------|-------|---------------|
| **ML-DSA-65** | FIPS 204 | Agent identity signing | 192-bit |
| **ML-DSA-87** | FIPS 204 | Model manifest signing | 256-bit |
| **ML-KEM-768** | FIPS 203 | Agent-to-agent key exchange | 192-bit |
| **SHA3-256** | FIPS 202 | File hashing, manifest integrity | 256-bit |
| **HMAC-SHA256** | RFC 2104 | Session cookie signing | 256-bit |

When liboqs is not installed, the library falls back to stub implementations with clear warnings. Install real PQC with `pip install quantumshield[pqc]`.

## HNDL Risk Scoring

Every model in the registry receives a Harvest Now, Decrypt Later (HNDL) risk assessment:

| Risk Level | Score | Meaning |
|------------|-------|---------|
| **CRITICAL** | 80-100 | Model weights will be decryptable before end of useful life |
| **HIGH** | 60-79 | Significant quantum exposure within projected shelf life |
| **MEDIUM** | 40-59 | Moderate risk, PQC migration recommended within 18 months |
| **LOW** | 0-39 | Limited quantum exposure at current threat projections |

Risk is calculated from: artifact sensitivity, shelf life, current encryption strength, and estimated time to cryptographically relevant quantum computers (CRQC).

## Transparency Log

All significant operations are recorded in an append-only, hash-chained transparency log:

```
Entry #15 ─────────────────────────────────────────
Seq:       15
Action:    model:signed
Actor:     did:key:z6MkqRYqQiSgFjBEp8Ps...
Target:    anthropic-claude-3-opus
Payload:   c8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3...
Previous:  b7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2...
Chain:     sha256(previous + payload) ✓
```

Each entry's hash chains to the previous, forming a verifiable sequence. Anyone can audit the log at [quantamrkt.com/transparency](https://quantamrkt.com/transparency) or via the API.

## Development

### Prerequisites

- Node.js 20+
- Python 3.10+
- npm

### Website

```bash
cd site
npm install
npm run dev        # Dev server at localhost:4321
npm run build      # Production build
```

### Python Library

```bash
cd lib
pip install -e ".[dev]"
quantumshield --help
pytest -v          # Run tests
ruff check src/    # Lint
```

### API Server

```bash
cd api
pip install -e ".[dev]"
uvicorn quantmrkt_api.main:app --reload  # Dev server at localhost:8000
pytest -v
```

### Deploy

```bash
cd site
npx wrangler deploy    # Deploy to Cloudflare Workers
```

Requires `CLOUDFLARE_API_TOKEN` for CI deploys and the following Wrangler secrets:

```bash
npx wrangler secret put GITHUB_CLIENT_SECRET
npx wrangler secret put SESSION_SECRET
```

## Regulatory Context

| Regulation | Deadline | Relevance |
|-----------|----------|-----------|
| **CNSA 2.0** | Jan 2027 | Mandates PQC for new systems in national security |
| **FIPS 203/204** | Aug 2024 (final) | ML-KEM and ML-DSA standardized by NIST |
| **EU AI Act** | 2025-2027 (phased) | Requires model provenance and traceability |
| **EO 14028** | Ongoing | Software supply chain security requirements |

## Contributing

We welcome contributions. Please see our [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes and add tests
4. Ensure CI passes (`npm run build` in site/, `pytest` in lib/ and api/)
5. Submit a pull request

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Links

- **Website**: [quantamrkt.com](https://quantamrkt.com)
- **Model Hub**: [quantamrkt.com/models](https://quantamrkt.com/models)
- **CLI Download**: [quantamrkt.com/download](https://quantamrkt.com/download)
- **Transparency Log**: [quantamrkt.com/transparency](https://quantamrkt.com/transparency)
- **API Docs**: [quantamrkt.com/docs/api-reference](https://quantamrkt.com/docs/api-reference)
- **PyPI**: [pypi.org/project/quantumshield](https://pypi.org/project/quantumshield)

---

<p align="center">
  <strong>Built for the post-quantum era. Launched in the classical one.</strong><br/>
  <sub>quantamrkt.com &bull; Dyber PQC &bull; Apache 2.0</sub>
</p>
