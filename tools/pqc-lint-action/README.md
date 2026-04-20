# PQC Lint

![PQC Native](https://img.shields.io/badge/PQC-Native-blue)
![ML-DSA / ML-KEM / SLH-DSA](https://img.shields.io/badge/suggests-ML--DSA%20%7C%20ML--KEM%20%7C%20SLH--DSA-green)
![License](https://img.shields.io/badge/License-Apache%202.0-orange)
![Version](https://img.shields.io/badge/version-0.1.0-lightgrey)

**Static analyzer for classical cryptography.** `pqc-lint` scans your source code for quantum-vulnerable crypto primitives — RSA, ECDSA, Ed25519, DH, ECDH, DSA, MD5, SHA-1 — across **six languages** (Python, JavaScript/TypeScript, Go, Rust, Java/Kotlin, C/C++) and points each finding at the matching NIST PQC replacement (**ML-DSA**, **ML-KEM**, **SLH-DSA**). Ships as both a drop-in **GitHub Action** and a standalone **CLI**. Emits **SARIF 2.1.0** for GitHub code scanning and inline **PR annotations** via workflow commands.

## The Problem

Every RSA keypair, every ECDSA signature, every ECDH handshake in your codebase is a time bomb. Once a cryptographically relevant quantum computer (CRQC) exists, Shor's algorithm breaks all of them. Data encrypted today under RSA-OAEP can be captured now and decrypted later ("harvest-now-decrypt-later"). Migration is not optional — it is a years-long engineering effort, and step one is knowing where the classical crypto actually lives.

## The Solution

`pqc-lint` gives you that inventory. Every PR gets scanned, every finding is mapped to a specific PQC replacement with rationale, and CI fails if critical quantum-vulnerable primitives land on `main`.

## Quick Start

### As a GitHub Action

Add `.github/workflows/pqc-lint.yml`:

```yaml
name: PQC Lint

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  pqc-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dyber-pqc/pqc-lint-action@v1
        with:
          path: '.'
          fail-on: 'high'
          upload-sarif: 'true'
```

Findings appear as:
- Inline PR annotations on the changed lines (via workflow commands)
- Entries in the GitHub Security tab (via SARIF upload)
- Failed check if any finding is at or above the `fail-on` threshold

### As a CLI

```bash
pip install pqc-lint

pqc-lint scan ./src
pqc-lint scan ./src --format sarif --output results.sarif
pqc-lint scan ./src --fail-on high
pqc-lint scan ./src --languages python,go
pqc-lint rules              # list all rules
pqc-lint --version
```

## Architecture

```
                                   +--------------------+
                                   |  CLI (click)       |
                                   |  action_runner     |
                                   +---------+----------+
                                             |
                                             v
            +----------+               +-----+------+              +------------+
            |  file    |               |            |              |            |
 path ----->|  walker  |--- file ----->|  Scanner   |--- matcher ->|  Patterns  |
            +----------+               |            |              |  (per-lang)|
               excludes                +-----+------+              +-----+------+
               globs                         |                           |
                                             | Finding                   | regex hits
                                             v                           v
                                        +----+-----+              +------+------+
                                        | ScanReport|<------------|   Rules     |
                                        +----+-----+              +-------------+
                                             |
             +----------------+--------------+---------------+----------------+
             |                |              |               |                |
             v                v              v               v                v
        +---------+    +----------+   +-----------+    +---------+      +-----------+
        |  text   |    |  json    |   |  sarif    |    |  github |      | (other)   |
        |(rich)   |    |          |   |  2.1.0    |    |  commds |      |           |
        +---------+    +----------+   +-----------+    +---------+      +-----------+
```

## Threat Model

| Adversary capability                       | pqc-lint claim                                                  |
| ------------------------------------------ | --------------------------------------------------------------- |
| Future CRQC (Shor's algorithm)             | Flags *every* known classical public-key primitive in the repo. |
| Insider commits RSA without review         | CI annotation + failed check at `fail-on: high`.                |
| Supply-chain slip (new dep uses ECDH)      | Regex patterns catch the import/call site on next PR.           |
| Obfuscated / dynamic crypto                | **Not in scope.** Static regex matching; does not evaluate code.|
| Binary-only / generated code               | **Not in scope.** Source files only.                            |

`pqc-lint` is a *detector* — not a remediation tool and not a proof of absence. It catches the common call sites in six languages across the dominant libraries. It is designed to have a low false-negative rate on idiomatic usage and a tolerable false-positive rate. Review each finding.

## Rule Catalog

### Signatures (broken by Shor's)

| Rule    | Severity | Primitive   | Replacement          |
| ------- | -------- | ----------- | -------------------- |
| PQC001  | CRITICAL | RSA signing | ML-DSA-65 (FIPS 204) |
| PQC002  | CRITICAL | ECDSA       | ML-DSA-65 (FIPS 204) |
| PQC003  | HIGH     | Ed25519     | ML-DSA-44 / SLH-DSA  |
| PQC004  | HIGH     | DSA         | ML-DSA-44 / SLH-DSA  |

### Key exchange (broken by Shor's)

| Rule    | Severity | Primitive   | Replacement          |
| ------- | -------- | ----------- | -------------------- |
| PQC101  | CRITICAL | ECDH        | ML-KEM-768 (FIPS 203)|
| PQC102  | CRITICAL | DH          | ML-KEM-768 (FIPS 203)|
| PQC103  | HIGH     | X25519      | ML-KEM-512 (FIPS 203)|

### Encryption (broken by Shor's)

| Rule    | Severity | Primitive          | Replacement           |
| ------- | -------- | ------------------ | --------------------- |
| PQC201  | CRITICAL | RSA-OAEP           | ML-KEM-768 (FIPS 203) |
| PQC202  | CRITICAL | RSA PKCS#1 v1.5    | ML-KEM-768 (FIPS 203) |

### Weak hashes

| Rule    | Severity | Primitive | Replacement            |
| ------- | -------- | --------- | ---------------------- |
| PQC301  | MEDIUM   | MD5       | SHA3-256 / SHAKE-256   |
| PQC302  | MEDIUM   | SHA-1     | SHA3-256 / SHAKE-256   |

## Supported Languages and Libraries

| Language             | Extensions                                      | Libraries detected                                                 |
| -------------------- | ----------------------------------------------- | ------------------------------------------------------------------ |
| Python               | `.py`                                           | `cryptography`, `pycryptodome`, `ecdsa`, `hashlib`                 |
| JavaScript/TypeScript| `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`    | Node `crypto`, Web Crypto API, `node-forge`, `tweetnacl`           |
| Go                   | `.go`                                           | `crypto/rsa`, `crypto/ecdsa`, `crypto/ed25519`, `crypto/md5`, etc. |
| Rust                 | `.rs`                                           | `rsa`, `ecdsa`, `ed25519-dalek`, `x25519-dalek`, `ring`            |
| Java / Kotlin        | `.java`, `.kt`                                  | `java.security`, `javax.crypto`, BouncyCastle                      |
| C / C++              | `.c`, `.cc`, `.cpp`, `.cxx`, `.h`, `.hpp`       | OpenSSL legacy API + EVP API                                       |

## Output Formats

| Format   | Best for                    | Contents                                                           |
| -------- | --------------------------- | ------------------------------------------------------------------ |
| `text`   | local terminal              | Rich-formatted table, grouped by file, with snippets and fixes.    |
| `json`   | custom tooling / piping     | Schema-v1.0 JSON: scan metadata + `findings[]` with full fields.   |
| `sarif`  | GitHub code scanning        | SARIF 2.1.0: rules catalog + results. Upload via `upload-sarif`.   |
| `github` | inside GitHub Actions       | `::error`, `::warning`, `::notice` workflow commands — PR inline.  |

## `fail-on` severity semantics

The action (or CLI) exits non-zero if **any** finding has severity **>=** the `fail-on` threshold.

| `fail-on`  | Fails CI when                                                                      |
| ---------- | ---------------------------------------------------------------------------------- |
| `critical` | A CRITICAL finding exists (RSA/ECDSA signing, ECDH, DH, RSA-OAEP).                 |
| `high`     | *(default)* A CRITICAL or HIGH finding exists (adds Ed25519, DSA, X25519).         |
| `medium`   | Adds MD5 / SHA-1.                                                                  |
| `low`      | Any finding at all.                                                                |
| `info`     | Any finding at all, including info-level annotations.                              |

## Excluded by default

```
**/.git/**
**/node_modules/**
**/__pycache__/**
**/.venv/**
**/venv/**
**/dist/**
**/build/**
**/.pytest_cache/**
**/.ruff_cache/**
**/*.min.js
```

Pass more globs via `exclude:` on the action or `--exclude` on the CLI.

## API Reference

```python
from pqc_lint import Scanner, Severity

scanner = Scanner(languages=("python", "go"))
report = scanner.scan_path("./src")

print(report.counts_by_severity())
# {'critical': 3, 'high': 1, 'medium': 2, 'low': 0, 'info': 0}

if report.has_failing(Severity.HIGH):
    raise SystemExit(1)

for f in report.findings:
    print(f.rule_id, f.file, f.line, f.suggestion)
```

Reporters:

```python
from pqc_lint.reporters import SarifReporter, JsonReporter, TextReporter

sarif_text = SarifReporter().render(report)
json_text  = JsonReporter().render(report)
text_out   = TextReporter().render(report)
```

## Development

```bash
cd tools/pqc-lint-action
pip install -e ".[dev]"
pytest -v
ruff check src/ tests/
```

## Contributing

Issues and PRs welcome. When adding a new rule or pattern:

1. Add the `Rule` entry in `src/pqc_lint/rules.py` with an appropriate ID range.
2. Add the regex pattern(s) to the per-language matcher(s) in `src/pqc_lint/patterns/`.
3. Add a test in `tests/test_scanner_<language>.py` that writes a minimal vulnerable file and asserts the rule fires.

## License

Apache 2.0. See `LICENSE`.

## Related

Part of the [QuantaMrkt](https://quantamrkt.com) open-source tools registry — a catalog of post-quantum security tooling.
