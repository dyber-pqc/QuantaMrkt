"""
Resolve the platform ML-DSA-87 keypair before signing.

Run once at the start of any CI job that needs to sign models. Resolution order:

  1. Fetch existing keypair from the QuantaMrkt API keystore
     (POST/GET /api/internal/platform-keys, X-Cron-Secret auth).
  2. Fall back to bootstrap env vars (BOOTSTRAP_PUBLIC_KEY / BOOTSTRAP_PRIVATE_KEY)
     and migrate them into the API on success.
  3. Generate a fresh ML-DSA-87 keypair and persist it to the API.

If FORCE_REGENERATE=true is set, step 3 runs unconditionally.

The resolved keypair is exported to subsequent CI steps via:
  - $GITHUB_ENV         (GitHub Actions)
  - $CI_BUILD_KEY_FILE  (GitLab CI — written as `KEY=value` lines, sourced by the next step)

If neither is set, the keys are written to ./.pqc_env in the current working
directory so the calling job can `source ./.pqc_env`.

Env vars:
  QUANTAMRKT_API_URL    base URL of the QuantaMrkt API (default https://quantamrkt.com)
  CRON_SECRET           required — auth for /api/internal/platform-keys
  BOOTSTRAP_PUBLIC_KEY  optional — hex pubkey from a GH secret (one-time migration path)
  BOOTSTRAP_PRIVATE_KEY optional — hex secret key (same)
  FORCE_REGENERATE      optional — "true" forces step 3
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

import oqs  # type: ignore[import-untyped]


API_URL = os.environ.get("QUANTAMRKT_API_URL", "https://quantamrkt.com")
CRON_SECRET = os.environ.get("CRON_SECRET", "")
FORCE = os.environ.get("FORCE_REGENERATE", "false").lower() == "true"


def main() -> None:
    if not CRON_SECRET:
        print("ERROR: CRON_SECRET not set — cannot use platform keystore", flush=True)
        sys.exit(1)

    avail = oqs.get_enabled_sig_mechanisms()
    alg = "ML-DSA-87" if "ML-DSA-87" in avail else "Dilithium5"
    print(f"Using algorithm: {alg}", flush=True)

    pk_hex = sk_hex = None

    # 1. API keystore
    if not FORCE:
        print("Step 1: fetching keys from platform API keystore...", flush=True)
        api_pk, api_sk = _fetch_from_api()
        if api_pk and api_sk and _keypair_works(alg, api_pk, api_sk):
            print("  ✓ Loaded compatible keypair from API", flush=True)
            pk_hex, sk_hex = api_pk, api_sk
        else:
            print("  ✗ API keystore empty or incompatible", flush=True)

    # 2. Bootstrap env vars
    if not pk_hex and not FORCE:
        print("Step 2: trying bootstrap env vars...", flush=True)
        boot_pk = os.environ.get("BOOTSTRAP_PUBLIC_KEY", "")
        boot_sk = os.environ.get("BOOTSTRAP_PRIVATE_KEY", "")
        if boot_pk and boot_sk and _keypair_works(alg, boot_pk, boot_sk):
            print("  ✓ Bootstrap env vars compatible — migrating to API", flush=True)
            pk_hex, sk_hex = boot_pk, boot_sk
            _push_to_api(pk_hex, sk_hex)
        else:
            print("  ✗ Bootstrap env vars unusable (likely stale liboqs encoding)", flush=True)

    # 3. Generate fresh keypair
    if not pk_hex:
        reason = "forced regeneration" if FORCE else "no compatible keypair found"
        print(f"Step 3: generating fresh keypair ({reason})...", flush=True)
        signer = oqs.Signature(alg)
        pk = signer.generate_keypair()
        sk = signer.export_secret_key()
        pk_hex = pk.hex()
        sk_hex = sk.hex()
        print(f"::add-mask::{sk_hex}")
        print(f"  ✓ Generated {alg} keypair (pk={len(pk)}B, sk={len(sk)}B)", flush=True)

        if _push_to_api(pk_hex, sk_hex):
            print("  ✓ Persisted to API keystore — future runs will reuse", flush=True)
        else:
            print("  ⚠ Could not persist to API — keys will be regenerated next run", flush=True)

    print(f"::add-mask::{sk_hex}")
    _export(pk_hex, sk_hex)

    print(f"\nReady to sign. Public key ({len(pk_hex) // 2} bytes):")
    print(f"  {pk_hex[:80]}...", flush=True)


def _keypair_works(alg: str, pk_hex: str, sk_hex: str) -> bool:
    """Round-trip sign/verify with the given hex keys against current liboqs."""
    try:
        pk = bytes.fromhex(pk_hex)
        sk = bytes.fromhex(sk_hex)
        signer = oqs.Signature(alg, sk)
        msg = b"platform-key-validation"
        sig = signer.sign(msg)
        verifier = oqs.Signature(alg)
        return bool(verifier.verify(msg, sig, pk))
    except Exception as exc:  # noqa: BLE001
        print(f"  → key validation failed: {exc}", flush=True)
        return False


def _fetch_from_api() -> tuple[str | None, str | None]:
    req = urllib.request.Request(
        f"{API_URL}/api/internal/platform-keys",
        headers={"X-Cron-Secret": CRON_SECRET},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            return data.get("public_key_hex"), data.get("private_key_hex")
    except urllib.error.HTTPError as e:
        print(f"  → API fetch HTTP {e.code}: {e.read().decode()[:200]}", flush=True)
    except Exception as e:  # noqa: BLE001
        print(f"  → API fetch failed: {e}", flush=True)
    return None, None


def _push_to_api(pk_hex: str, sk_hex: str) -> bool:
    body = json.dumps({"public_key_hex": pk_hex, "private_key_hex": sk_hex}).encode()
    req = urllib.request.Request(
        f"{API_URL}/api/internal/platform-keys",
        data=body,
        method="POST",
        headers={
            "X-Cron-Secret": CRON_SECRET,
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            print(f"  → API store HTTP {resp.status}", flush=True)
            return resp.status in (200, 201)
    except Exception as e:  # noqa: BLE001
        print(f"  → API store failed: {e}", flush=True)
        return False


def _export(pk_hex: str, sk_hex: str) -> None:
    """Write the resolved keypair to wherever the calling CI system reads env from."""
    gh_env = os.environ.get("GITHUB_ENV")
    if gh_env:
        with open(gh_env, "a") as f:
            f.write(f"PLATFORM_ML_DSA_PUBLIC_KEY={pk_hex}\n")
            f.write(f"PLATFORM_ML_DSA_PRIVATE_KEY={sk_hex}\n")
        return

    # GitLab CI: write to .pqc_env in the project dir for `source` by the next step
    target = os.environ.get("CI_BUILD_KEY_FILE", ".pqc_env")
    with open(target, "w") as f:
        f.write(f"export PLATFORM_ML_DSA_PUBLIC_KEY={pk_hex}\n")
        f.write(f"export PLATFORM_ML_DSA_PRIVATE_KEY={sk_hex}\n")
    print(f"  → wrote keypair to {target} (source it in the next step)", flush=True)


if __name__ == "__main__":
    main()
