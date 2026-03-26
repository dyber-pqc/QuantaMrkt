"""
PQC Signing Service -- signs model manifests with real ML-DSA-87 (FIPS 204).

Requires: pip install quantumshield[pqc]   (which pulls in liboqs-python)

Environment variables
---------------------
PLATFORM_ML_DSA_PUBLIC_KEY   hex-encoded ML-DSA-87 public key
PLATFORM_ML_DSA_PRIVATE_KEY  hex-encoded ML-DSA-87 secret key
QUANTAMRKT_API_URL           base URL of the QuantaMrkt API  (default: https://quantamrkt.com)
QUANTAMRKT_API_TOKEN         bearer token for authenticated API calls
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from typing import Any

import httpx

# liboqs MUST be available -- the [pqc] extra installs it
try:
    import oqs  # type: ignore[import-untyped]
except ImportError:
    print(
        "ERROR: liboqs-python is not installed.\n"
        "       Install it with:  pip install liboqs-python\n"
        "       Or:               pip install quantumshield[pqc]"
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PLATFORM_DID = "did:web:quantamrkt.com:chain:authority"
API_URL = os.environ.get("QUANTAMRKT_API_URL", "https://quantamrkt.com")
API_TOKEN = os.environ.get("QUANTAMRKT_API_TOKEN")
ALGORITHM = "ML-DSA-87"
OQS_ALGORITHM = "Dilithium5"  # ML-DSA-87 = Dilithium5 in liboqs


# ---------------------------------------------------------------------------
# Signing service
# ---------------------------------------------------------------------------


class PQCSigningService:
    """Platform-level PQC signing service using ML-DSA-87 via liboqs."""

    def __init__(self) -> None:
        self.public_key: bytes = b""
        self.private_key: bytes = b""
        self._load_or_generate_key()

    # -- key management -----------------------------------------------------

    def _load_or_generate_key(self) -> None:
        """Load the platform keypair from env vars, or generate a fresh one."""
        pk_hex = os.environ.get("PLATFORM_ML_DSA_PUBLIC_KEY")
        sk_hex = os.environ.get("PLATFORM_ML_DSA_PRIVATE_KEY")

        if pk_hex and sk_hex:
            self.public_key = bytes.fromhex(pk_hex)
            self.private_key = bytes.fromhex(sk_hex)
            print(f"Loaded existing {ALGORITHM} platform key ({len(self.public_key)} bytes)")
        else:
            signer = oqs.Signature(OQS_ALGORITHM)
            self.public_key = signer.generate_keypair()
            self.private_key = signer.export_secret_key()
            print(f"Generated new {ALGORITHM} platform keypair")
            print(f"PUBLIC KEY  (hex, {len(self.public_key)} bytes):")
            print(self.public_key.hex())
            print(f"PRIVATE KEY (hex, {len(self.private_key)} bytes):")
            print(self.private_key.hex())
            print(
                "\nSave both as GitHub secrets:\n"
                "  PLATFORM_ML_DSA_PUBLIC_KEY\n"
                "  PLATFORM_ML_DSA_PRIVATE_KEY"
            )

    # -- crypto operations --------------------------------------------------

    def sign(self, message: bytes) -> bytes:
        """Sign *message* with ML-DSA-87 and return the raw signature bytes."""
        signer = oqs.Signature(OQS_ALGORITHM, self.private_key)
        return signer.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify an ML-DSA-87 *signature* over *message*."""
        verifier = oqs.Signature(OQS_ALGORITHM)
        return verifier.verify(message, signature, self.public_key)

    def get_public_key_hex(self) -> str:
        return self.public_key.hex()

    # -- model signing ------------------------------------------------------

    def sign_model(self, model_slug: str, manifest_data: dict[str, Any]) -> dict[str, str]:
        """Build a canonical message for *model_slug*, sign it, and return metadata."""
        canonical = json.dumps(
            {
                "slug": model_slug,
                "files": [
                    {
                        "filename": f["filename"],
                        "hash": f.get("sha3_256_hash", ""),
                        "size": f.get("size", 0),
                    }
                    for f in manifest_data.get("files", [])
                ],
                "version": manifest_data.get("latest_version", "1.0.0"),
            },
            sort_keys=True,
        )

        message = hashlib.sha3_256(canonical.encode()).digest()
        signature = self.sign(message)

        # Self-check
        if not self.verify(message, signature):
            raise RuntimeError("Self-verification failed -- signing key may be corrupt")

        return {
            "signer_did": PLATFORM_DID,
            "algorithm": ALGORITHM,
            "signature_hex": signature.hex(),
            "attestation_type": "pqc_registry",
            "message_hash": message.hex(),
            "public_key_hex": self.get_public_key_hex(),
        }

    # -- batch signing via API ----------------------------------------------

    def sign_all_models(self) -> dict[str, Any]:
        """Fetch every model from the QuantaMrkt API and sign it."""
        headers: dict[str, str] = {}
        if API_TOKEN:
            headers["Authorization"] = f"Bearer {API_TOKEN}"

        resp = httpx.get(f"{API_URL}/api/models?limit=200", headers=headers, timeout=30)
        resp.raise_for_status()
        models: list[dict[str, Any]] = resp.json().get("models", [])

        print(f"Found {len(models)} models to sign")

        results: dict[str, Any] = {"signed": 0, "errors": [], "skipped": 0}

        for model in models:
            slug: str = model["slug"]
            try:
                detail_resp = httpx.get(
                    f"{API_URL}/api/models/{slug}", headers=headers, timeout=30
                )
                if detail_resp.status_code != 200:
                    results["errors"].append(f"{slug}: HTTP {detail_resp.status_code}")
                    continue

                detail = detail_resp.json()

                # Skip if already has a real PQC signature
                existing_sigs = detail.get("signatures", [])
                if any(s.get("attestation_type") == "pqc_registry" for s in existing_sigs):
                    results["skipped"] += 1
                    continue

                sig_data = self.sign_model(slug, detail)

                push_resp = httpx.post(
                    f"{API_URL}/api/models/{slug}/sign",
                    json=sig_data,
                    headers=headers,
                    timeout=30,
                )

                if push_resp.status_code in (200, 201):
                    results["signed"] += 1
                    print(f"  Signed: {slug}")
                else:
                    results["errors"].append(
                        f"{slug}: push failed HTTP {push_resp.status_code}"
                    )

            except Exception as exc:  # noqa: BLE001
                results["errors"].append(f"{slug}: {exc}")

        return results


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------


def main() -> None:
    service = PQCSigningService()

    if "--generate-key" in sys.argv:
        print(f"\nPlatform {ALGORITHM} Public Key:\n{service.get_public_key_hex()}\n")
        return

    if "--sign-all" in sys.argv:
        results = service.sign_all_models()
        print(
            f"\nResults: {results['signed']} signed, "
            f"{results['skipped']} skipped, "
            f"{len(results['errors'])} errors"
        )
        for err in results["errors"]:
            print(f"  Error: {err}")
        return

    if "--verify" in sys.argv:
        idx = sys.argv.index("--verify")
        if idx + 1 >= len(sys.argv):
            print("Usage: --verify <slug>")
            sys.exit(1)
        slug = sys.argv[idx + 1]
        resp = httpx.get(f"{API_URL}/api/models/{slug}/verify", timeout=30)
        print(json.dumps(resp.json(), indent=2))
        return

    print("Usage:")
    print("  python -m quantumshield.signing_service --generate-key")
    print("  python -m quantumshield.signing_service --sign-all")
    print("  python -m quantumshield.signing_service --verify <slug>")


if __name__ == "__main__":
    main()
