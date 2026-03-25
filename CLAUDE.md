# QuantaMrkt Development Guide

## Monorepo Structure
- `site/` — Astro + Cloudflare Workers (public site + dashboard)
- `lib/` — QuantumShield Python library
- `api/` — FastAPI backend

## Commands

### Site
```bash
cd site && npm run dev     # Dev server
cd site && npm run build   # Production build
cd site && npx wrangler deploy  # Deploy to CF Workers
```

### Python Library
```bash
cd lib && pip install -e ".[dev]"
quantumshield --help
cd lib && pytest
```

### API
```bash
cd api && pip install -e ".[dev]"
uvicorn quantmrkt_api.main:app --reload
cd api && pytest
```

## Conventions
- Python: ruff for linting/formatting, pydantic for models
- TypeScript: strict mode, Tailwind for styling
- Git: conventional commits, no force push to main
- Commits must NOT include Co-Authored-By lines
- `.claude/` must never be committed
