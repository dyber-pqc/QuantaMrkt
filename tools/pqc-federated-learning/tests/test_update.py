"""Tests for ClientUpdate / GradientTensor / ClientUpdateMetadata."""

from __future__ import annotations

import pytest

from pqc_federated_learning import (
    ClientUpdate,
    ClientUpdateMetadata,
    GradientTensor,
)


def test_gradient_tensor_shape_validation() -> None:
    # Mismatched shape/values should raise
    with pytest.raises(ValueError):
        GradientTensor(name="w", shape=(2, 2), values=(1.0, 2.0, 3.0))


def test_gradient_tensor_roundtrip() -> None:
    t = GradientTensor(name="w", shape=(2, 2), values=(1.0, 2.0, 3.0, 4.0))
    d = t.to_dict()
    t2 = GradientTensor.from_dict(d)
    assert t == t2


def test_content_hash_is_deterministic() -> None:
    meta = ClientUpdateMetadata(
        client_did="did:pqaid:abc",
        round_id="r1",
        model_id="m1",
        num_samples=10,
    )
    tensors = [GradientTensor(name="w", shape=(2,), values=(1.0, 2.0))]
    h1 = ClientUpdate.compute_content_hash(meta, tensors, "2026-01-01T00:00:00+00:00")
    h2 = ClientUpdate.compute_content_hash(meta, tensors, "2026-01-01T00:00:00+00:00")
    assert h1 == h2
    assert len(h1) == 64  # sha3-256 hex


def test_content_hash_changes_with_values() -> None:
    meta = ClientUpdateMetadata(
        client_did="did:pqaid:abc",
        round_id="r1",
        model_id="m1",
        num_samples=10,
    )
    t1 = [GradientTensor(name="w", shape=(2,), values=(1.0, 2.0))]
    t2 = [GradientTensor(name="w", shape=(2,), values=(1.0, 3.0))]
    h1 = ClientUpdate.compute_content_hash(meta, t1, "2026-01-01T00:00:00+00:00")
    h2 = ClientUpdate.compute_content_hash(meta, t2, "2026-01-01T00:00:00+00:00")
    assert h1 != h2


def test_create_populates_content_hash() -> None:
    meta = ClientUpdateMetadata(
        client_did="did:pqaid:abc",
        round_id="r1",
        model_id="m1",
        num_samples=10,
    )
    tensors = [GradientTensor(name="w", shape=(2,), values=(1.0, 2.0))]
    u = ClientUpdate.create(meta, tensors)
    assert u.content_hash != ""
    assert u.created_at != ""
    # content hash matches computation
    assert u.content_hash == ClientUpdate.compute_content_hash(meta, tensors, u.created_at)


def test_client_update_roundtrip() -> None:
    meta = ClientUpdateMetadata(
        client_did="did:pqaid:abc",
        round_id="r1",
        model_id="m1",
        num_samples=10,
        epochs=3,
        local_loss=0.25,
    )
    tensors = [GradientTensor(name="w", shape=(2,), values=(1.0, 2.0))]
    u = ClientUpdate.create(meta, tensors)
    u.signer_did = "did:pqaid:abc"
    u.algorithm = "ML-DSA-65"
    u.signature = "deadbeef"
    u.public_key = "cafe"
    u.signed_at = "2026-01-01T00:00:00+00:00"

    d = u.to_dict()
    u2 = ClientUpdate.from_dict(d)
    assert u2.metadata == u.metadata
    assert u2.tensors == u.tensors
    assert u2.content_hash == u.content_hash
    assert u2.signature == u.signature
    assert u2.algorithm == u.algorithm
