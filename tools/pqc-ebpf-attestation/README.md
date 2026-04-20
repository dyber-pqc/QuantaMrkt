# PQC eBPF Attestation

![PQC Native](https://img.shields.io/badge/PQC-Native-blue)
![ML-DSA-65](https://img.shields.io/badge/ML--DSA--65-FIPS%20204-green)
![eBPF](https://img.shields.io/badge/eBPF-load%20gate-purple)
![License](https://img.shields.io/badge/License-Apache%202.0-orange)
![Version](https://img.shields.io/badge/version-0.1.0-lightgrey)

**A post-quantum signed load gate for eBPF programs on AI inference servers.** eBPF lets code run inside the Linux kernel; it is phenomenal for observability and security, and catastrophic as a supply-chain attack vector. A malicious eBPF program loaded on an inference host can silently intercept model calls, exfiltrate weights out of `/dev/nvidia*` handles, or rewrite output tokens on the way back to the user - with no trace at the application layer. This library is the cryptographic envelope that sits *before* `bpf_prog_load()`: every program is ML-DSA signed, every signer has a DID, every load attempt is matched against a `LoadPolicy` and appended to an audit log. The actual kernel integration (an LSM hook, a pre-load userspace verifier, or a Kubernetes admission controller) is the user's job; this library gives you the data structures, signing, verification, and policy engine to plug into that integration.

## The Problem

AI inference servers are a uniquely sensitive target for eBPF-based attacks:

- **Weight exfiltration.** A `kprobe` or `tracing` program attached to a CUDA or cgroup memory path can read GPU-adjacent pages and stream out model weights over a socket.
- **Silent tampering.** An `XDP` or `sched_cls` program can rewrite outbound JSON from an inference API mid-flight.
- **Observability poisoning.** A `perf_event` program can filter out its own footprint from the very telemetry the defender relies on.
- **Supply chain.** eBPF programs shipped as `.bpf.o` objects by vendors, operators, or observability agents have no standard signing model today; the kernel happily loads anything with `CAP_BPF`.

Pre-quantum signatures (RSA, ECDSA, Ed25519) also carry a long-term forgeability risk: signed eBPF binaries retain trust for years, well into the timeline where a cryptographically relevant quantum computer could forge new ones retroactively.

## The Solution

- **ML-DSA (FIPS 204)** signatures over a canonical manifest: `metadata + SHA3-256(bytecode) + size`. The signature does not bloat with the bytecode.
- **DID-based signer identity** via `quantumshield.identity.agent.AgentIdentity` - every signer has a stable `did:pqaid:<hash>` that policies can reason about.
- **`LoadPolicy` with ordered rules** - each rule covers a set of `BPFProgramType`s, an allow-list of signer DIDs, an optional signature requirement, and a max-size cap. First matching rule wins; no match falls through to a configurable default (deny by default).
- **Append-only `AttestationLog`** - every load attempt is recorded with its signer, hash, decision, reason, and actor, regardless of whether it was accepted.
- **CLI (`pqc-bpf sign | verify | info`)** for ops teams.

## Installation

```bash
pip install pqc-ebpf-attestation
```

Development:

```bash
pip install -e ".[dev]"
```

## Quick Start

```python
from quantumshield.identity.agent import AgentIdentity

from pqc_ebpf_attestation import (
    AttestationLog,
    BPFProgram,
    BPFProgramMetadata,
    BPFProgramType,
    BPFSigner,
    BPFVerifier,
    LoadPolicy,
    PolicyRule,
)

# 1. Load and sign a compiled eBPF object.
metadata = BPFProgramMetadata(
    name="trace_sys_enter_read",
    program_type=BPFProgramType.KPROBE,
    attach_point="sys_enter_read",
    author="ops-team",
)
program = BPFProgram.from_file(metadata, "trace.bpf.o")

identity = AgentIdentity.create("bpf-signer", capabilities=["sign"])
signer = BPFSigner(identity)
signed = signer.sign(program)

# 2. Verify independently.
result = BPFVerifier.verify(signed)
assert result.valid

# 3. Enforce a policy at load time.
policy = LoadPolicy().add_rule(
    PolicyRule(
        program_types=(BPFProgramType.KPROBE, BPFProgramType.TRACING),
        allowed_signers=frozenset({identity.did}),
    )
)
log = AttestationLog()
decision, reason = policy.evaluate(signed)
log.log(signed, decision, reason, actor="admission-controller")

if decision.value == "deny":
    raise SystemExit(f"blocked: {reason}")

# ... now hand `signed.program.bytecode` to bpf_prog_load().
```

## Architecture

```
 +-----------------+     +-----------+     +--------------------+
 |  Dev / CI       | --> | bpftool,  | --> | .bpf.o object      |
 |  writes BPF C   |     | clang BPF |     | (compiled)         |
 +-----------------+     +-----------+     +---------+----------+
                                                     |
                                                     v
                                          +---------------------+
                                          | BPFSigner (ML-DSA)  |
                                          | signs canonical     |
                                          | manifest (hash+meta)|
                                          +----------+----------+
                                                     |
                                                     v
                                          +---------------------+
                                          | SignedBPFProgram    |
                                          | ships with .bpf.o   |
                                          +----------+----------+
                                                     |
  deployment / OCI bundle / admission webhook        |
                                                     v
 +------------------+    +----------------+   +----------------+
 | LoadPolicy       |--->| BPFVerifier    |-->| AttestationLog |
 | (rules, allow-   |    | checks sig +   |   | (append-only)  |
 |  list, size caps)|    | hash match     |   +----------------+
 +--------+---------+    +-------+--------+
          |                      |
          | allow                | deny
          v                      v
 +-------------------+   +------------------+
 | bpf_prog_load()   |   | rejected before  |
 | kernel accepts    |   | reaching kernel  |
 +-------------------+   +------------------+
```

## Cryptography

| Primitive                | Algorithm                  | Source                         |
|--------------------------|----------------------------|--------------------------------|
| Digital signature        | ML-DSA-65 (FIPS 204)       | `quantumshield.core.signatures`|
| Bytecode hash            | SHA3-256                   | `hashlib.sha3_256`             |
| Canonical manifest       | Sorted JSON, UTF-8         | Deterministic, compact         |
| Identity                 | `did:pqaid:<sha3-256(pk)>` | `quantumshield.identity.agent` |

The signature does not cover the raw bytecode - only `metadata + SHA3-256(bytecode) + size`. Bytecode integrity is checked by recomputing the hash at verification time. This keeps the signature envelope small (stable at a few hundred bytes of metadata + a ~3 KB ML-DSA-65 signature), regardless of the size of the eBPF object.

## Policy Model

A `LoadPolicy` is an ordered list of `PolicyRule`s. Each rule declares:

- **`program_types`** - which `BPFProgramType` values the rule covers (e.g., `(KPROBE, TRACING)`).
- **`allowed_signers`** - a `frozenset[str]` of DIDs permitted to sign programs for these types. Empty set means "any verified signer".
- **`require_signature`** - whether an invalid signature forces a deny (default `True`; turning this off is only for testing).
- **`max_bytecode_size`** - hard cap on bytecode size; default 2 MiB. Prevents signing-gate bypass via oversize or compressed programs.

Evaluation:

1. Iterate rules in order. First rule whose `program_types` matches is the chosen rule.
2. If no rule matches, return `default_decision` (default `DENY`).
3. Apply the matching rule: size check, signature check, allow-list check.
4. First failing check returns `DENY` with a human-readable reason.

`policy.enforce(signed)` raises `UntrustedSignerError` if the signer is not in the allow-list, or `PolicyDeniedError` for any other denial.

## CLI Reference

```bash
# Sign a compiled BPF object.
pqc-bpf sign trace.bpf.o --name trace-read --type kprobe --author ops-team

# Verify an envelope. Exit 0 if valid, 1 otherwise.
pqc-bpf verify trace.bpf.o.sig.json

# Pretty-print metadata without verifying.
pqc-bpf info trace.bpf.o.sig.json

# Show version.
pqc-bpf --version
```

## Integration Notes

This library is intentionally **userspace-only and kernel-agnostic**. It does *not* hook `bpf()` syscalls, does not ship an LSM module, and does not link against `libbpf`. Real enforcement requires wiring one of:

- **A pre-load userspace verifier.** A small daemon that replaces direct `bpf_prog_load()` calls in your deployment: callers pass `SignedBPFProgram` envelopes, the daemon verifies and enforces, and only then calls into libbpf. Simplest model, easiest to audit.
- **An LSM hook.** Kernels with `CONFIG_BPF_LSM=y` can attach a BPF LSM program to `bpf_prog_load` that rejects unsigned programs - with the signature verifier itself running in userspace over a ring buffer. Defense-in-depth but more involved.
- **An admission controller.** For Kubernetes, gate CRDs that reference BPF programs (Cilium, Falco, Tetragon, bpfman) through a webhook that verifies and logs before the DaemonSet even schedules.

In every case, this library provides the envelope format, the verifier, the policy engine, and the audit log. The trust root is the set of signer DIDs you choose to put in your `LoadPolicy`.

## Threat Model

| Threat                                                    | Mitigation                                                      |
|-----------------------------------------------------------|-----------------------------------------------------------------|
| Unsigned attacker-supplied `.bpf.o` loaded via CAP_BPF    | `require_signature=True`; no envelope -> no load                |
| Legit-looking program signed by a rogue insider           | Allow-list of DIDs; rogue DID not permitted                     |
| Bytecode swapped after signing (TOCTOU)                   | SHA3-256 hash in signed manifest; verifier recomputes           |
| Signature replayed on a different program                 | Canonical manifest binds signature to exact metadata + hash     |
| Oversize program smuggling raw weights back to attacker   | `max_bytecode_size` cap                                         |
| Future quantum adversary forges ECDSA-signed BPF object   | ML-DSA-65 is NIST FIPS 204, resistant to Shor's algorithm       |
| Tampering with audit record                               | In-memory append-only; sink to WORM store in production         |

Out of scope: anything the kernel verifier itself misses (bounds-checker bypasses, stack overflow via helpers, JIT spraying). The library trusts the kernel's BPF verifier to do its job once a program is loaded.

## Why PQC Matters for eBPF

eBPF programs are *long-lived trust artifacts*. A kernel probe shipped with an observability agent today can remain deployed for a decade across thousands of hosts. If the signature that authorizes it is RSA-2048 or secp256r1, a cryptographically relevant quantum computer appearing within that window lets any attacker forge *new* programs that pass the same gate - with no warning, because the forgery is indistinguishable from a legitimate signature. Rotating that gate to ML-DSA-65 from day one keeps the trust boundary intact on the ten-year horizon where eBPF-based infrastructure actually operates.

## Examples

- `examples/sign_and_verify.py` - sign, serialize, deserialize, verify a synthetic program.
- `examples/enforce_load_policy.py` - three signers (two trusted, one rogue) evaluated against a policy, audit log printed.
- `examples/tampered_bytecode_rejected.py` - mutate bytecode post-sign; hash-consistency check fires.

## License

Apache-2.0. See `LICENSE`.
