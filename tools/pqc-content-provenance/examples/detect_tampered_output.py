"""Detect tampered AI output.

Run:  python examples/detect_tampered_output.py
"""

from __future__ import annotations

from quantumshield import AgentIdentity

from pqc_content_provenance import (
    ContentManifest,
    GenerationContext,
    ManifestSigner,
    ModelAttribution,
)


def main() -> None:
    identity = AgentIdentity.create("signer")
    signer = ManifestSigner(identity)

    original = b"The patient has low risk of myocardial infarction."
    manifest = ContentManifest.create(
        content=original,
        content_type="text/plain",
        model_attribution=ModelAttribution(
            model_did="did:pqaid:medical-ai",
            model_name="Medical-Diagnostics-v2",
            model_version="2.3",
        ),
        generation_context=GenerationContext(
            prompt_hash="c" * 64,
            parameters={"temperature": 0.1},
            generated_at="2026-04-20T12:00:00Z",
        ),
    )
    signed = signer.sign(manifest)

    # Attacker modifies output (swaps "low" for "high")
    tampered = b"The patient has high risk of myocardial infarction."

    result = ManifestSigner.verify(signed, tampered)
    if result.valid:
        print("[FAIL] Tampering was not detected!")
    else:
        print("[OK] Tampering detected:")
        print(f"  content_hash_match: {result.content_hash_match}")
        print(f"  signature_match:    {result.signature_match}")
        print(f"  error:              {result.error}")


if __name__ == "__main__":
    main()
