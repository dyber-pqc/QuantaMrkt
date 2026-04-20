"""Tests for Corpus and CorpusManifest."""

from __future__ import annotations

from dataclasses import replace

from quantumshield.identity.agent import AgentIdentity

from pqc_rag_signing import (
    ChunkMetadata,
    ChunkSigner,
    Corpus,
    CorpusManifest,
)


def _make_corpus(
    identity: AgentIdentity,
    texts: dict[str, list[str]],
) -> Corpus:
    c = Corpus(name="test", identity=identity)
    for source, chunks in texts.items():
        c.add_document(source, chunks)
    return c


def test_corpus_sign_all(
    ingest_identity: AgentIdentity,
    sample_corpus_texts: dict[str, list[str]],
) -> None:
    corpus = _make_corpus(ingest_identity, sample_corpus_texts)
    signed = corpus.sign_all()
    total = sum(len(v) for v in sample_corpus_texts.values())
    assert len(signed) == total
    for c in signed:
        assert c.corpus_id == corpus.corpus_id
        assert c.signer_did == ingest_identity.did


def test_build_manifest(
    ingest_identity: AgentIdentity,
    sample_corpus_texts: dict[str, list[str]],
) -> None:
    corpus = _make_corpus(ingest_identity, sample_corpus_texts)
    corpus.sign_all()
    manifest = corpus.build_manifest()
    assert manifest.corpus_id == corpus.corpus_id
    assert manifest.name == "test"
    assert manifest.chunk_count == sum(
        len(v) for v in sample_corpus_texts.values()
    )
    expected_root = CorpusManifest.compute_root(manifest.chunk_hashes)
    assert manifest.root == expected_root
    assert manifest.signer_did == ingest_identity.did


def test_verify_manifest_valid(
    ingest_identity: AgentIdentity,
    sample_corpus_texts: dict[str, list[str]],
) -> None:
    corpus = _make_corpus(ingest_identity, sample_corpus_texts)
    corpus.sign_all()
    manifest = corpus.build_manifest()
    assert Corpus.verify_manifest(manifest)


def test_verify_manifest_tampered_root_fails(
    ingest_identity: AgentIdentity,
    sample_corpus_texts: dict[str, list[str]],
) -> None:
    corpus = _make_corpus(ingest_identity, sample_corpus_texts)
    corpus.sign_all()
    manifest = corpus.build_manifest()
    bogus_root = "0" * 64
    tampered = replace(manifest, root=bogus_root)
    assert not Corpus.verify_manifest(tampered)


def test_verify_manifest_tampered_chunk_list_fails(
    ingest_identity: AgentIdentity,
    sample_corpus_texts: dict[str, list[str]],
) -> None:
    corpus = _make_corpus(ingest_identity, sample_corpus_texts)
    corpus.sign_all()
    manifest = corpus.build_manifest()
    # Append a fake chunk pair - root still matches the old one so the
    # recomputed root differs.
    bad_list = list(manifest.chunk_hashes) + [("fake-chunk", "00" * 32)]
    tampered = replace(manifest, chunk_hashes=bad_list)
    assert not Corpus.verify_manifest(tampered)


def test_verify_chunks_against_manifest_all_present(
    ingest_identity: AgentIdentity,
    sample_corpus_texts: dict[str, list[str]],
) -> None:
    corpus = _make_corpus(ingest_identity, sample_corpus_texts)
    signed = corpus.sign_all()
    manifest = corpus.build_manifest()
    ok, missing = Corpus.verify_chunks_against_manifest(signed, manifest)
    assert ok
    assert missing == []


def test_verify_chunks_against_manifest_extra_chunk_detected(
    ingest_identity: AgentIdentity,
    sample_corpus_texts: dict[str, list[str]],
) -> None:
    corpus = _make_corpus(ingest_identity, sample_corpus_texts)
    signed = corpus.sign_all()
    manifest = corpus.build_manifest()

    # Insert a chunk that is NOT committed in the manifest
    rogue_signer = ChunkSigner(ingest_identity)
    rogue = rogue_signer.sign_chunk(
        "not in manifest",
        ChunkMetadata(source="rogue.txt", chunk_index=0, total_chunks=1),
    )
    chunks_with_rogue = signed + [rogue]

    ok, missing = Corpus.verify_chunks_against_manifest(
        chunks_with_rogue, manifest
    )
    assert not ok
    assert rogue.chunk_id in missing


def test_manifest_root_deterministic(ingest_identity: AgentIdentity) -> None:
    pairs_a = [
        ("chunk-a", "aa" * 32),
        ("chunk-b", "bb" * 32),
        ("chunk-c", "cc" * 32),
    ]
    pairs_b = list(reversed(pairs_a))  # different order
    assert CorpusManifest.compute_root(pairs_a) == CorpusManifest.compute_root(
        pairs_b
    )
