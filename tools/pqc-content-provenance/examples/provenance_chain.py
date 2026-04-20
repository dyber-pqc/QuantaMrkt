"""Chain of provenance: original AI output -> human-edited derivation.

Run:  python examples/provenance_chain.py
"""

from __future__ import annotations

from quantumshield import AgentIdentity

from pqc_content_provenance import (
    AIGeneratedAssertion,
    ContentManifest,
    GenerationContext,
    ManifestSigner,
    ModelAttribution,
    ProvenanceChain,
)


def main() -> None:
    model_identity = AgentIdentity.create("llama-3")
    editor_identity = AgentIdentity.create("human-editor-alice")
    model_signer = ManifestSigner(model_identity)
    editor_signer = ManifestSigner(editor_identity)

    # Step 1: AI generates original
    original_content = b"Draft press release: QuantaMrkt ships tool #4."
    attribution = ModelAttribution(
        model_did=model_identity.did,
        model_name="Llama-3-8B-Instruct",
        model_version="1.0",
    )
    ctx = GenerationContext(
        prompt_hash="d" * 64,
        parameters={"temperature": 0.6},
        generated_at="2026-04-20T12:00:00Z",
    )
    original = ContentManifest.create(
        content=original_content,
        content_type="text/plain",
        model_attribution=attribution,
        generation_context=ctx,
        assertions=[
            AIGeneratedAssertion(model_name="Llama-3-8B-Instruct", model_version="1.0")
        ],
    )
    original_signed = model_signer.sign(original)

    # Step 2: Human edits content and re-signs with reference to previous manifest
    edited_content = b"Press release: QuantaMrkt ships tool #4 (Signed AI Content Provenance)."
    edited = ContentManifest.create(
        content=edited_content,
        content_type="text/plain",
        model_attribution=attribution,  # still based on Llama-3 originally
        generation_context=ctx,
        assertions=[
            AIGeneratedAssertion(
                model_name="Llama-3-8B-Instruct",
                model_version="1.0",
                human_edited=True,
            ),
        ],
        previous_manifest_id=original_signed.manifest_id,
    )
    edited_signed = editor_signer.sign(edited)

    chain = ProvenanceChain()
    chain.add(original_signed)
    chain.add(edited_signed)

    ok, errors = chain.verify_chain()
    print(f"chain length:  {len(chain.links)}")
    print(f"chain valid:   {ok}")
    if errors:
        for e in errors:
            print(f"  error: {e}")

    for link in chain.links:
        m = link.manifest
        print(f"\n  - manifest_id:  {m.manifest_id}")
        print(f"    signer:       {m.signer_did}")
        print(f"    content_hash: {m.content_hash[:16]}...")
        print(f"    prev:         {m.previous_manifest_id}")


if __name__ == "__main__":
    main()
