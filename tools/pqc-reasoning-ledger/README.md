# pqc-reasoning-ledger

![PQC Native](https://img.shields.io/badge/PQC-Native-6b21a8)
![ML-DSA-65](https://img.shields.io/badge/Signature-ML--DSA--65-0ea5e9)
![SHA3-256](https://img.shields.io/badge/Hash-SHA3--256-22c55e)
![Merkle](https://img.shields.io/badge/Proofs-Merkle-f59e0b)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Version](https://img.shields.io/badge/version-0.1.0-7c3aed)

**PQC-signed neurosymbolic reasoning ledger.** Sign chain-of-thought steps in real time
during AI inference. Produces legally defensible, quantum-safe reasoning trails for
regulated industries where the reasoning chain itself must survive a decade of
adversarial review.

As AI is used for high-stakes reasoning (legal analysis, medical diagnosis, financial
risk, regulatory decisions), courts and regulators are asking *"how did the model reach
this conclusion?"* This library records every step of the model's thought process as a
hash-chained, Merkle-rooted, ML-DSA-65 signed **reasoning trace** that is tamper-evident
end-to-end and verifiable by third parties without any trust in the original recorder.

## Install

```bash
pip install pqc-reasoning-ledger
```

## Quick start

```python
from quantumshield.identity.agent import AgentIdentity
from pqc_reasoning_ledger import ReasoningRecorder, TraceVerifier

identity = AgentIdentity.create("legal-advisor-signer")
rec = ReasoningRecorder(identity)
rec.begin_trace(
    model_did="did:pqaid:gpt-legal",
    model_version="2.1",
    task="contract-review",
    domain="legal",
)

rec.record_observation("Contract contains a liquidated damages clause capping at $1M.")
rec.record_retrieval("NY CPLR 3215; Truck Rent-A-Center v. Puritan Farms 2nd (1977).")
rec.record_hypothesis("Clause is likely enforceable if sum is reasonable relative to harm.")
rec.record_deduction("Given $1M cap and projected $1.2M harm, clause is reasonable.")
rec.record_self_critique("Should also check whether plaintiff must mitigate damages.")
rec.record_decision("Recommend signing with carve-out for force-majeure events.")

sealed = rec.seal()

# External verifier, days or years later:
result = TraceVerifier.verify(sealed)
assert result.fully_verified
```

The `sealed` value is a self-contained, post-quantum-signed proof of the *exact sequence
of reasoning steps* the model took. Altering any step, adding a step, dropping a step,
reordering steps, or forging the signature will all cause `TraceVerifier.verify()` to
return `valid=False` with a specific error string.

## Architecture

```
  +---------------------+    record_*    +---------------------+
  |   Model inference   | -------------> |  ReasoningRecorder  |
  |   (chain-of-thought)|                |                     |
  +---------------------+                |  ReasoningTrace     |
                                         |   step_1  --+       |
                                         |   step_2  --+ hash  |
                                         |   step_3  --+ chain |
                                         |    ...              |
                                         +---------+-----------+
                                                   | seal()
                                                   v
                                  +----------------+-----------------+
                                  |          SealedTrace             |
                                  |  final_chain_hash                |
                                  |  merkle_root (over step_hashes)  |
                                  |  ML-DSA-65 signature             |
                                  |  signer public key               |
                                  +----------------+-----------------+
                                                   | transport / archive
                                                   v
                                  +----------------+-----------------+
                                  |  TraceVerifier (independent)     |
                                  |   1. chain integrity             |
                                  |   2. merkle root                 |
                                  |   3. ML-DSA signature            |
                                  +----------------------------------+
                                                   |
                                                   v
                                       fully_verified: True / False
```

Each step records `SHA3-256(previous_step_hash || canonical_bytes(step))`, so tampering
with any intermediate step breaks every downstream hash. The `merkle_root` over step
hashes enables **selective disclosure**: you can prove a single step was in the trace
(e.g. "the model considered case law X") via `ReasoningProver.prove_step()` without
revealing the other steps.

## Step kinds

The symbolic vocabulary for reasoning steps (`StepKind`):

| Kind | Meaning |
| --- | --- |
| `thought` | Free-form reasoning statement |
| `observation` | Observation about input or retrieved data |
| `hypothesis` | A tentative conclusion to evaluate |
| `deduction` | Logical deduction from prior steps |
| `retrieval` | Fetching external knowledge (RAG, memory, citation) |
| `tool-call` | Calling an external tool or function |
| `tool-result` | Result returned by a tool call |
| `self-critique` | Model critiquing its own prior step |
| `refinement` | Updated answer after critique |
| `decision` | Final decision or answer |
| `meta` | Metadata about the run itself |

## Cryptography

| Layer | Primitive |
| --- | --- |
| Content hash | SHA3-256 of UTF-8 step text |
| Step hash | SHA3-256( previous_step_hash \|\| canonical_json(step_payload) ) |
| Merkle tree | SHA3-256 with RFC6962-style domain separation (0x00 leaves, 0x01 internal) |
| Trace seal signature | ML-DSA-65 (NIST FIPS 204) over SHA3-256 of sealed canonical bytes |
| Identity | Quantumshield `AgentIdentity` + DID (`did:pqaid:...`) |

All signatures are produced via `quantumshield.core.signatures.sign` and verify via
`quantumshield.core.signatures.verify`, so the verification path has no dependency on
the original signer process.

## Threat model

| Attack | Detected by |
| --- | --- |
| Retroactive edit of an intermediate step | Chain check: step hash and all downstream hashes break |
| Swapped step at position k | Chain check: previous_step_hash at k+1 no longer matches |
| Inserted step | Chain check: step_number off by one; step_hash invalid |
| Dropped step | `final_chain_hash`, Merkle root, and signature all mismatch |
| Re-ordered steps | Chain check fails; Merkle root fails |
| Forged ML-DSA signature | ML-DSA-65 verify fails (PQ-secure) |
| Substituted public key | Signature still has to verify against attached key, but the DID is bound in the signed payload and independent public-key-infrastructure should be consulted for signer provenance |

What is **not** in scope: confidentiality of reasoning steps (this library is about
integrity, not secrecy - encrypt separately if needed), and mitigations against a
compromised signer (rotate and revoke via your identity infrastructure).

## API reference

### `ReasoningRecorder(identity: AgentIdentity)`

- `begin_trace(model_did, model_version, task="", actor_did="", session_id="", domain="")`
- `record(kind, content, references=None, confidence=1.0, metadata=None)`
- `record_thought(content, **kw)` / `record_observation` / `record_hypothesis`
  / `record_deduction` / `record_retrieval` / `record_tool_call` / `record_tool_result`
  / `record_self_critique` / `record_refinement` / `record_decision`
- `seal() -> SealedTrace`

### `ReasoningTrace`

- `metadata: TraceMetadata`, `steps: list[ReasoningStep]`, `sealed: bool`
- `current_hash -> str` (chain-tip hash)
- `append(step)` - raises `ChainBrokenError` / `TraceSealedError` on violation
- `to_dict() -> dict`

### `SealedTrace`

- Dataclass with `metadata`, `steps`, `final_chain_hash`, `merkle_root`, `step_count`,
  `sealed_at`, `signer_did`, `algorithm`, `signature`, `public_key`
- `to_dict()` / `to_json()` / `from_dict()` / `from_json()`
- `canonical_bytes() -> bytes` (deterministic payload that is signed)

### `TraceVerifier`

- `verify(sealed) -> VerificationResult` with `valid`, `signature_valid`,
  `chain_intact`, `merkle_root_valid`, `step_count`, `error`, and `fully_verified`
- `verify_or_raise(sealed)` - raises `SignatureVerificationError` on failure

### `ReasoningProver`

- `prove_step(sealed, step_id) -> StepInclusionProof`
- `verify_proof(proof) -> bool`

## Why PQC for reasoning trails

AI liability law is accelerating. The EU AI Act, NYC Local Law 144, the FDA's AI/ML
Software Pre-Cert guidance, and state-level medical and insurance rules all push toward
**retrospective explainability of AI decisions**. A signed reasoning trace has to remain
verifiable for the full litigation horizon - often 6-10+ years - which is well inside
the timeline where cryptographically relevant quantum computers become a risk to
classical-signature archives. ML-DSA-65 is NIST-standardized (FIPS 204) and provides
integrity guarantees that outlive the archival window, without requiring re-signing
the corpus under a new algorithm.

This library is **ahead of the curve**: the reasoning trails it produces today will
still be defensible evidence when quantum-capable adversaries exist.

## Examples

- `examples/legal_contract_review.py` - 6-step legal reasoning trace
- `examples/medical_diagnosis.py` - 7-step medical reasoning with inclusion proof
- `examples/tamper_detection.py` - demonstrate detection of a flipped byte

## License

Apache 2.0 - see `LICENSE`.
