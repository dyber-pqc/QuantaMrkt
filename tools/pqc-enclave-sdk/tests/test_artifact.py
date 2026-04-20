"""Tests for artifact data structures."""

from __future__ import annotations

from pqc_enclave_sdk import (
    ArtifactKind,
    ArtifactMetadata,
    EnclaveArtifact,
    EncryptedArtifact,
)


def test_artifact_metadata_to_dict_roundtrip() -> None:
    meta = ArtifactMetadata(
        artifact_id="urn:pqc-enclave-art:abc",
        name="llama-3",
        kind=ArtifactKind.MODEL_WEIGHTS,
        version="1.0",
        app_bundle_id="com.example.llm",
        size_bytes=1024,
        created_at="2026-01-01T00:00:00+00:00",
        device_id="iphone-1",
        tags=("prod", "int4"),
    )
    d = meta.to_dict()
    assert d["kind"] == "model-weights"
    assert d["tags"] == ["prod", "int4"]
    assert d["name"] == "llama-3"
    assert d["size_bytes"] == 1024


def test_encrypted_artifact_from_to_dict_roundtrip() -> None:
    meta = ArtifactMetadata(
        artifact_id="urn:pqc-enclave-art:xyz",
        name="tokenizer",
        kind=ArtifactKind.TOKENIZER,
    )
    enc = EncryptedArtifact(
        metadata=meta,
        nonce="00" * 12,
        ciphertext="deadbeef",
        content_hash="cafebabe",
        key_id="urn:pqc-enclave-key:1",
    )
    d = enc.to_dict()
    rebuilt = EncryptedArtifact.from_dict(d)
    assert rebuilt.metadata.name == "tokenizer"
    assert rebuilt.metadata.kind == ArtifactKind.TOKENIZER
    assert rebuilt.nonce == enc.nonce
    assert rebuilt.ciphertext == enc.ciphertext
    assert rebuilt.content_hash == enc.content_hash
    assert rebuilt.key_id == enc.key_id


def test_enclave_artifact_sha3_256_hex_is_deterministic() -> None:
    meta = ArtifactMetadata(
        artifact_id="id",
        name="x",
        kind=ArtifactKind.OTHER,
    )
    a = EnclaveArtifact(metadata=meta, content=b"hello world")
    b = EnclaveArtifact(metadata=meta, content=b"hello world")
    assert a.sha3_256_hex() == b.sha3_256_hex()
    assert len(a.sha3_256_hex()) == 64


def test_artifact_kind_enum_round_trips() -> None:
    for kind in ArtifactKind:
        assert ArtifactKind(kind.value) == kind
    assert ArtifactKind("model-weights") == ArtifactKind.MODEL_WEIGHTS
    assert ArtifactKind.CREDENTIAL.value == "credential"
