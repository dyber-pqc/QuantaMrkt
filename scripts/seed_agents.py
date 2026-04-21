#!/usr/bin/env python3
"""Generate real ML-DSA keypairs for each agent + sign with platform key + push to D1.

Requires:
  - liboqs-python (0.14.1) with matching liboqs C library (0.14.0)
  - Env: QUANTAMRKT_API_URL, CRON_SECRET (for authenticated bulk write),
         PLATFORM_ML_DSA_PRIVATE_KEY, PLATFORM_ML_DSA_PUBLIC_KEY

Flow:
  1. Walk agents/<name>/identity.json files
  2. For each, generate a fresh ML-DSA keypair (algorithm per identity file)
  3. Derive DID = did:pqaid:sha3_256(public_key)
  4. Sign the canonical agent payload with the PLATFORM ML-DSA-87 key
     (this is the "registry attestation" — proves QuantaMrkt registered it)
  5. Write updated identity.json (public fields only — NO private key on disk)
  6. POST to the QuantaMrkt registry API via X-Cron-Secret to update the DB
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx
import oqs

REPO_ROOT = Path(__file__).resolve().parent.parent
AGENTS_DIR = REPO_ROOT / "agents"

API_URL = os.environ.get("QUANTAMRKT_API_URL", "https://quantamrkt.com")
CRON_SECRET = os.environ.get("CRON_SECRET", "")
PLATFORM_SK_HEX = os.environ.get("PLATFORM_ML_DSA_PRIVATE_KEY", "")
PLATFORM_PK_HEX = os.environ.get("PLATFORM_ML_DSA_PUBLIC_KEY", "")

# liboqs algorithm name mapping
ALGO_MAP = {
    "ML-DSA-44": "Dilithium2",
    "ML-DSA-65": "Dilithium3",
    "ML-DSA-87": "Dilithium5",
}


def liboqs_alg(name: str) -> str:
    """Return the liboqs mechanism name for an ML-DSA alg string."""
    enabled = set(oqs.get_enabled_sig_mechanisms())
    if name in enabled:
        return name
    fallback = ALGO_MAP.get(name)
    if fallback and fallback in enabled:
        return fallback
    raise RuntimeError(f"Neither {name} nor {fallback} is enabled in liboqs. Have: {sorted(enabled)[:5]}")


def generate_keypair(algorithm: str) -> tuple[bytes, bytes]:
    """Generate a real ML-DSA keypair via liboqs. Returns (public_key, private_key)."""
    alg = liboqs_alg(algorithm)
    signer = oqs.Signature(alg)
    pk = signer.generate_keypair()
    sk = signer.export_secret_key()
    return pk, sk


def did_from_public_key(pk: bytes) -> str:
    """did:pqaid:<sha3-256(pubkey)>"""
    return f"did:pqaid:{hashlib.sha3_256(pk).hexdigest()}"


def canonical_agent_bytes(agent: dict[str, Any]) -> bytes:
    """Deterministic bytes the platform signs."""
    payload = {
        "name": agent["name"],
        "did": agent["did"],
        "algorithm": agent["algorithm"],
        "public_key": agent["public_key"],
        "capabilities": sorted(agent["capabilities"]),
        "status": agent["status"],
        "created_at": agent["created_at"],
        "registry_url": agent["registry_url"],
    }
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def platform_sign(payload: bytes) -> str:
    """Sign payload digest with the platform ML-DSA-87 key. Returns hex signature."""
    if not PLATFORM_SK_HEX or not PLATFORM_PK_HEX:
        raise RuntimeError("Platform signing keys not set in environment")
    alg = liboqs_alg("ML-DSA-87")
    sk = bytes.fromhex(PLATFORM_SK_HEX)
    pk = bytes.fromhex(PLATFORM_PK_HEX)
    signer = oqs.Signature(alg, sk)
    digest = hashlib.sha3_256(payload).digest()
    sig = signer.sign(digest)
    # Self-verify
    verifier = oqs.Signature(alg)
    if not verifier.verify(digest, sig, pk):
        raise RuntimeError("Platform self-verify failed — signing key corrupt")
    return sig.hex()


def update_registry(agent: dict[str, Any]) -> None:
    """Write the agent record to the QuantaMrkt D1 via the bulk-register endpoint."""
    headers = {"Content-Type": "application/json"}
    if CRON_SECRET:
        headers["X-Cron-Secret"] = CRON_SECRET
    body = {
        "name": agent["name"],
        "did": agent["did"],
        "algorithm": agent["algorithm"],
        "public_key_hex": agent["public_key"],
        "capabilities": agent["capabilities"],
        "status": agent["status"],
        "source_url": agent["registry_url"],
        "platform_signer_did": agent["platform_signer_did"],
        "platform_signature": agent["platform_signature"],
    }
    resp = httpx.post(
        f"{API_URL}/api/agents/seed",
        json=body,
        headers=headers,
        timeout=30,
    )
    resp.raise_for_status()


def process_agent(identity_path: Path) -> None:
    print(f"\n[{identity_path.parent.name}]")
    identity = json.loads(identity_path.read_text())

    # Regenerate keypair (replaces placeholder)
    algorithm = identity.get("algorithm", "ML-DSA-65")
    pk, sk_unused = generate_keypair(algorithm)   # noqa: F841 (sk discarded on purpose)
    did = did_from_public_key(pk)

    # Source URL on GitHub
    slug = identity_path.parent.name
    github_url = f"https://github.com/dyber-pqc/QuantaMrkt/tree/main/agents/{slug}"

    # Build canonical record
    now = os.environ.get("GITHUB_SHA", "bootstrap")[:12]
    record = {
        "name": identity["name"],
        "did": did,
        "algorithm": algorithm,
        "public_key": pk.hex(),
        "capabilities": identity["capabilities"],
        "status": identity.get("status", "active"),
        "created_at": f"seeded-at-sha-{now}",
        "registry_url": github_url,
    }

    # Sign with platform key
    signature_hex = platform_sign(canonical_agent_bytes(record))
    record["platform_signature"] = signature_hex
    record["platform_signer_did"] = "did:web:quantamrkt.com"

    # Write back — public fields only, no private key on disk
    identity_path.write_text(json.dumps(record, indent=2) + "\n")
    print(f"  did      = {did}")
    print(f"  alg      = {algorithm}  (liboqs: {liboqs_alg(algorithm)})")
    print(f"  pubkey   = {pk[:12].hex()}...  ({len(pk)} bytes)")
    print(f"  sig[:24] = {signature_hex[:24]}...")
    print(f"  source   = {github_url}")

    # Push to D1
    try:
        update_registry(record)
        print("  [OK] registry updated")
    except httpx.HTTPStatusError as exc:
        print(f"  [WARN] registry update failed: HTTP {exc.response.status_code}: {exc.response.text[:200]}")
    except Exception as exc:
        print(f"  [WARN] registry update failed: {exc}")


def main() -> int:
    if not AGENTS_DIR.exists():
        print(f"ERROR: {AGENTS_DIR} does not exist")
        return 1

    identities = sorted(AGENTS_DIR.glob("*/identity.json"))
    if not identities:
        print("No agent identity.json files found")
        return 1

    print(f"Seeding {len(identities)} agents with real ML-DSA keys...")
    print(f"  API: {API_URL}")
    print(f"  Platform key: {len(PLATFORM_PK_HEX) // 2} bytes public / "
          f"{len(PLATFORM_SK_HEX) // 2} bytes private")

    for p in identities:
        try:
            process_agent(p)
        except Exception as exc:
            print(f"  [FAIL] {p.parent.name}: {exc}")

    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
