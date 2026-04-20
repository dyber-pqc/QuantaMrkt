# PQC Immutable AI Audit Log (Filesystem)

![PQC Native](https://img.shields.io/badge/PQC-Native-blue)
![ML-DSA-65](https://img.shields.io/badge/ML--DSA--65-FIPS%20204-green)
![SHA3-256](https://img.shields.io/badge/Merkle-SHA3--256-green)
![EU AI Act Ready](https://img.shields.io/badge/EU%20AI%20Act-Audit%20Trail-purple)
![License](https://img.shields.io/badge/License-Apache%202.0-orange)
![Version](https://img.shields.io/badge/version-0.1.0-lightgrey)

**Tamper-evident audit log for AI inference events, designed for legal discovery.** When an AI system denies a loan, flags a medical claim, moderates content, or calls a tool, that decision needs to survive 15+ years of potential litigation. This library writes each inference to an append-only segmented file, builds an SHA3-256 Merkle tree per segment, signs the segment header with **ML-DSA** (FIPS 204), and chains every segment to the previous one by root hash. Any single bit flipped anywhere in the log is detected on verification.

## The Problem

Regulators and plaintiff's lawyers are converging on the same demand: *show us the inference log*. The EU AI Act (Article 12) requires high-risk AI systems to keep automatically-generated logs for the lifetime of the system. US class-action litigation against AI lenders, insurers, and content platforms routinely subpoenas inference histories. Existing solutions fall short:

- **Application-DB logs** are mutable — a DBA or a compromised service can edit them without trace.
- **Cloud log services** are opaque to the model operator; if the provider loses them you have no recourse.
- **RSA/ECDSA-signed** archives decay the moment a cryptographically relevant quantum computer exists — signatures made today must still verify in 2040.

## The Solution

A pure-Python library with an append-only on-disk layout:

- Each `InferenceEvent` stores SHA3-256 hashes of the input/output (not the raw content — privacy-preserving) plus model DID, actor DID, decision label, timestamp.
- `LogAppender` writes events as JSON-Lines into `segment-NNNNN.log`. When the rotation policy fires (events, bytes, or age), a `SegmentHeader` is built: Merkle root over every leaf hash, plus `previous_segment_root` chaining to the prior segment. The header is signed with ML-DSA and written to `segment-NNNNN.sig.json`.
- `LogReader.verify_chain()` walks every segment, recomputes each Merkle root, verifies each ML-DSA signature, and confirms every chain link. One mutation anywhere fails verification.
- `InclusionProver` produces `O(log n)` proofs that a specific event was in a specific segment — useful when you must surrender a single decision to a court without leaking the surrounding log.

## Installation

```bash
pip install pqc-audit-log-fs
```

Development:

```bash
pip install -e ".[dev]"
```

## Quick Start

```python
from quantumshield.identity.agent import AgentIdentity
from pqc_audit_log_fs import (
    InferenceEvent, LogAppender, LogReader, RotationPolicy,
)

signer = AgentIdentity.create(name="audit-signer")

with LogAppender(
    "./audit-log",
    signer,
    rotation=RotationPolicy(max_events_per_segment=10_000),
) as appender:
    for decision in your_decisions:
        appender.append(InferenceEvent.create(
            model_did="did:pqaid:credit-model-v3",
            model_version="3.2.1",
            input_bytes=decision.input_blob,
            output_bytes=decision.output_blob,
            decision_type="classification",
            decision_label=decision.label,        # 'approve' | 'deny'
            actor_did=decision.user_did,
            session_id=decision.session_id,
        ))

reader = LogReader("./audit-log")
ok, errors = reader.verify_chain()
assert ok, errors
```

## Architecture

```
  Inference Service                           Verifier / Court / Auditor
  ----------------                            ---------------------------

  event -> LogAppender.append()
             |
             |  jsonl line
             v
    segment-NNNNN.log  (append-only)
             |
             |  rotation trigger
             v
    [merkle root over leaf hashes]
             |
             |  ML-DSA sign
             v
    segment-NNNNN.sig.json  <-------------->  LogReader.verify_chain()
             |                                       |
             |  previous_segment_root                |  recompute roots
             v                                       |  verify ML-DSA sigs
    segment-(N+1)*****.log -> .sig.json              |  check chain links
             |                                       v
             |                                    ok / errors
             v
        (optional) MerkleAnchor
          -> external transparency log
```

## Cryptography

| Primitive                   | Algorithm      | Purpose                                   |
|-----------------------------|----------------|-------------------------------------------|
| Leaf hash                   | SHA3-256       | `SHA3-256(0x00 ‖ canonical(event))`       |
| Internal Merkle node        | SHA3-256       | `SHA3-256(0x01 ‖ left ‖ right)`           |
| Segment signature           | ML-DSA-65      | over `SHA3-256(canonical(header))`        |
| Cross-segment chaining      | SHA3-256       | `header.previous_segment_root`            |

Leaves and internal nodes use domain-separation prefixes to prevent second-preimage attacks. Segments chain like a blockchain: rewriting segment `k` forces every subsequent `previous_segment_root` to also be rewritten, and every subsequent ML-DSA signature to be forged.

## Segment File Layout

```
audit-log/
  segment-00001.log              JSON-Lines, one InferenceEvent per line
  segment-00001.sig.json         signed SegmentHeader
  segment-00002.log
  segment-00002.sig.json
  ...
```

A `segment-NNNNN.sig.json` looks like:

```json
{
  "segment_id": "segment-00001",
  "segment_number": 1,
  "created_at": "2026-04-20T12:00:00+00:00",
  "sealed_at":  "2026-04-20T13:00:00+00:00",
  "event_count": 10000,
  "merkle_root": "a1b2c3...",
  "previous_segment_root": "",
  "log_id": "urn:pqc-audit-log:...",
  "signer_did": "did:pqaid:...",
  "algorithm": "ML-DSA-65",
  "signature": "ff...",
  "public_key": "aa..."
}
```

## Rotation Policy

`RotationPolicy` triggers a seal when **any** threshold is crossed:

| Field                       | Default      | Meaning                                   |
|-----------------------------|--------------|-------------------------------------------|
| `max_events_per_segment`    | 10,000       | Seal after N events                       |
| `max_bytes_per_segment`     | 10 MB        | Seal after N bytes of JSONL               |
| `max_segment_age_seconds`   | 3600 (1h)    | Seal after time elapsed                   |

## Threat Model

| Attack                                      | How we detect it                                                |
|---------------------------------------------|-----------------------------------------------------------------|
| Flip a byte in a sealed `.log` file         | Merkle root mismatch in `verify_segment`                        |
| Delete an event line from a sealed segment  | Merkle root mismatch                                            |
| Swap a whole segment for a forged one       | Chain break: `previous_segment_root` of next segment mismatches |
| Forge a signature today                     | ML-DSA-65 — no known classical or quantum break                 |
| Re-sign after tamper using the signer's key | Requires private key exfiltration; out of scope                 |
| Delete trailing segments                    | Detectable if segment roots are anchored externally (`MerkleAnchor`) |

The log is designed to be post-quantum hard: ML-DSA-65 targets NIST security category 3, equivalent to AES-192 classical / post-quantum. Signatures made today remain verifiable after cryptographically relevant quantum computers arrive.

## EU AI Act Mapping

| Requirement (Article 12, "Record-keeping")       | This library                                |
|---------------------------------------------------|---------------------------------------------|
| Automatic generation of logs                      | `LogAppender.append()`                      |
| Logs appropriate to intended purpose              | `InferenceEvent.metadata` is free-form      |
| Logs kept for the lifetime of the system          | Append-only segments; no size cap           |
| Logs traceable to a specific system version       | `model_did` + `model_version` per event     |
| Logs enabling post-market monitoring              | `LogReader.verify_chain()` for spot audits  |
| Integrity protection                              | SHA3-256 + ML-DSA-65 + cross-segment chain  |

Combine with `MerkleAnchor` to publish segment roots to a public transparency log (blockchain, Rekor, etc.) for externally-anchored non-repudiation.

## CLI Reference

```
pqc-audit verify <log_dir>
pqc-audit prove  <log_dir> <segment_number> <event_id>
pqc-audit info   <log_dir>
```

Example:

```
$ pqc-audit info ./audit-log
log_dir: ./audit-log
segments: 3
  segment 00001 events=10000 root=a1b2c3d4e5f6a7b8... prev=<genesis>       sealed_at=2026-04-20T13:00:00+00:00
  segment 00002 events=10000 root=b2c3d4e5f6a7b8c9... prev=a1b2c3d4e5f6... sealed_at=2026-04-20T14:00:00+00:00
  segment 00003 events= 4231 root=c3d4e5f6a7b8c9d0... prev=b2c3d4e5f6a7... sealed_at=2026-04-20T15:00:00+00:00

$ pqc-audit verify ./audit-log
[OK] all 3 segments verify
```

## API Reference

### `InferenceEvent`

| Field                  | Type       | Description                                   |
|------------------------|------------|-----------------------------------------------|
| `event_id`             | str        | `urn:pqc-audit-evt:<hex>`                     |
| `timestamp`            | str (ISO)  | UTC wall-clock                                |
| `model_did`            | str        | `did:pqaid:...` identifying the model         |
| `model_version`        | str        | Semver or hash of model binary                |
| `input_hash`           | str        | SHA3-256 hex of canonical input               |
| `output_hash`          | str        | SHA3-256 hex of canonical output              |
| `reasoning_chain_hash` | str        | SHA3-256 hex over chain-of-thought            |
| `decision_type`        | str        | e.g. `classification`, `generation`           |
| `decision_label`       | str        | e.g. `approve`, `deny`                        |
| `actor_did`            | str        | DID of the user/agent that invoked the model  |
| `session_id`           | str        | Free-form session identifier                  |
| `metadata`             | dict       | Free-form metadata                            |

### `LogAppender`

- `append(event)` — append one event; may trigger a seal.
- `seal_current_segment()` — force-seal now.
- `close()` — seal and flush; also invoked by `__exit__`.

### `LogReader`

- `list_segments() -> list[int]`
- `read_header(n) -> SegmentHeader`
- `read_segment(n) -> AuditSegment`
- `verify_segment(n) -> bool`
- `verify_chain() -> (ok, errors)`

### `InclusionProver`

- `prove_event(segment_number, event_id) -> InclusionProof`
- `verify_proof(event, proof) -> bool`

### `MerkleAnchor` / `AnchorSink`

- Pluggable sink interface for publishing segment roots to an external
  transparency log (blockchain, Rekor-style log, internal KMS, etc.).

### `FilesystemGuard`

- Best-effort OS-level enforcement: `chmod` on all platforms; `chattr +a/+i`
  on Linux; `chflags uchg` on macOS.

## Why PQC for Audit Logs

AI liability litigation runs on timescales of a decade or more:

- A 2026 loan denial may surface in a 2035 class-action settlement.
- A 2027 medical model may face a 2040 product-liability suit.
- EU AI Act retention is tied to the *lifetime of the system* — potentially 20+ years.

Classical signatures made in 2026 will not survive a cryptographically relevant quantum computer ("Q-day") if one arrives mid-retention-window. ML-DSA-65 is the right default: NIST-standardized, FIPS 204, security category 3.

## Examples

- `examples/basic_log.py` — Write 30 events with rotation every 10, verify chain.
- `examples/prove_inclusion.py` — Build and verify an inclusion proof for event #25.
- `examples/tamper_detection.py` — Mutate a JSONL line; show `verify_chain()` flagging the specific segment.

## License

Apache 2.0
