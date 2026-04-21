"""Research Assistant -- reads a signed corpus, emits a signed summary."""

from __future__ import annotations

import json
from pathlib import Path

from quantumshield.identity.agent import AgentIdentity

from pqc_rag_signing import ChunkMetadata, ChunkSigner
from pqc_content_provenance import (
    AIGeneratedAssertion,
    ContentManifest,
    GenerationContext,
    ManifestSigner,
    ModelAttribution,
)


IDENTITY_FILE = Path(__file__).parent / "identity.json"


def load_identity() -> AgentIdentity:
    data = json.loads(IDENTITY_FILE.read_text())
    return AgentIdentity.create(data["name"], capabilities=data["capabilities"])


def retrieve_signed(agent: AgentIdentity) -> list[str]:
    """Sign a tiny mock corpus and return the retrieved texts."""
    signer = ChunkSigner(agent, corpus_id="urn:corpus:pqc-whitepapers")
    corpus = [
        ("Lattice signatures rely on Module-LWE hardness.", "ml-dsa-primer.md"),
        ("ML-DSA-87 targets NIST security category 5.", "ml-dsa-primer.md"),
    ]
    out: list[str] = []
    for idx, (text, source) in enumerate(corpus):
        chunk = signer.sign_chunk(
            text,
            ChunkMetadata(source=source, chunk_index=idx, total_chunks=len(corpus)),
        )
        out.append(chunk.text)
    return out


def summarize(agent: AgentIdentity, retrieved: list[str]) -> ContentManifest:
    summary = ("Summary: " + " ".join(retrieved)).encode()
    manifest = ContentManifest.create(
        content=summary,
        content_type="text/plain",
        model_attribution=ModelAttribution(
            model_did=agent.did, model_name="research-assistant", model_version="1.0"
        ),
        generation_context=GenerationContext(generated_at="2026-04-20T12:00:00Z"),
        assertions=[AIGeneratedAssertion(
            model_name="research-assistant",
            model_version="1.0",
            generator_type="text",
        )],
    )
    return ManifestSigner(agent).sign(manifest)


def main() -> None:
    agent = load_identity()
    print(f"[agent] {agent.did}")

    retrieved = retrieve_signed(agent)
    print(f"[rag] retrieved_chunks={len(retrieved)} (all PQC-signed)")

    signed = summarize(agent, retrieved)
    print(f"[summary] manifest_id={signed.manifest_id}")
    print(f"[summary] signature={signed.signature[:24]}...")


if __name__ == "__main__":
    main()
