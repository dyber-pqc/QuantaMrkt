"""Tests for the SHA3-256 Merkle tree."""

from __future__ import annotations

import hashlib

import pytest

from pqc_audit_log_fs.errors import AuditLogError
from pqc_audit_log_fs.merkle import (
    build_merkle_proof,
    compute_merkle_root,
    verify_inclusion,
)


def _hex(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def test_empty_raises() -> None:
    with pytest.raises(AuditLogError):
        compute_merkle_root([])


def test_single_leaf_root() -> None:
    leaf = _hex(b"only-one")
    root = compute_merkle_root([leaf])
    # A single leaf's root is SHA3-256(0x00 || leaf_bytes)
    expected = hashlib.sha3_256(b"\x00" + bytes.fromhex(leaf)).hexdigest()
    assert root == expected


def test_proof_roundtrip_even_count() -> None:
    leaves = [_hex(f"leaf-{i}".encode()) for i in range(8)]
    root = compute_merkle_root(leaves)
    for idx in range(len(leaves)):
        proof = build_merkle_proof(leaves, idx, root)
        assert proof.root == root
        assert proof.tree_size == 8
        assert verify_inclusion(proof)


def test_proof_roundtrip_odd_count() -> None:
    leaves = [_hex(f"leaf-{i}".encode()) for i in range(7)]
    root = compute_merkle_root(leaves)
    for idx in range(len(leaves)):
        proof = build_merkle_proof(leaves, idx, root)
        assert verify_inclusion(proof)


def test_tampered_sibling_fails() -> None:
    leaves = [_hex(f"leaf-{i}".encode()) for i in range(5)]
    proof = build_merkle_proof(leaves, 2)
    assert verify_inclusion(proof)
    # Mutate first sibling
    tampered = proof.siblings[:]
    tampered[0] = "00" * 32
    from pqc_audit_log_fs.merkle import InclusionProof

    bad = InclusionProof(
        leaf_hash=proof.leaf_hash,
        index=proof.index,
        tree_size=proof.tree_size,
        root=proof.root,
        siblings=tampered,
        directions=proof.directions,
    )
    assert not verify_inclusion(bad)
