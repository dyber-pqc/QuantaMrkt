# QuantaMrkt

**The Quantum-Safe AI Marketplace**

QuantaMrkt is the trust layer for AI in the post-quantum era. We provide PQC-native infrastructure, tools, and a marketplace to secure the entire AI ecosystem with post-quantum cryptography.

## Products

- **PQ-AID** — Post-quantum agent identity infrastructure (ML-DSA signing, DID-compatible, delegation chains)
- **Migrator** — AI agent that executes PQC migration across codebases (not just audits)
- **Shield Registry** — HNDL-resistant AI model protection with quantum-safe signing

## Repository Structure

```
quantmrkt/
├── site/       # Public website & dashboard (Astro + Cloudflare Workers)
├── lib/        # QuantumShield Python library
├── api/        # Backend API (FastAPI)
└── .github/    # CI/CD workflows
```

## Quick Start

### Website (Astro)

```bash
cd site
npm install
npm run dev
```

### Python Library

```bash
cd lib
pip install -e ".[dev]"
quantumshield --help
```

### API Server

```bash
cd api
pip install -e ".[dev]"
uvicorn quantmrkt_api.main:app --reload
```

## Tech Stack

- **Frontend**: Astro, Tailwind CSS, TypeScript
- **Deployment**: Cloudflare Workers
- **Library**: Python, ML-DSA/ML-KEM via liboqs
- **Backend**: FastAPI, PostgreSQL, Redis
- **CI/CD**: GitHub Actions

## Links

- Website: [quantmrkt.com](https://quantmrkt.com)
- Docs: [quantmrkt.com/docs](https://quantmrkt.com/docs)

## License

Apache 2.0 — see [LICENSE](LICENSE)
