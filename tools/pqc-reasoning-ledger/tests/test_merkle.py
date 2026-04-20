"""Tests for Merkle tree primitives."""

from __future__ import annotations

import hashlib

import pytest

from pqc_reasoning_ledger import (
    ReasoningLedgerError,
    build_proof,
    compute_merkle_root,
    verify_inclusion,
)


def _leaf(i: int) -> str:
    return hashlib.sha3_256(f"leaf-{i}".encode()).hexdigest()


def test_empty_raises() -> None:
    with pytest.raises(ReasoningLedgerError):
        compute_merkle_root([])


def test_single_leaf_root() -> None:
    leaf = _leaf(0)
    root = compute_merkle_root([leaf])
    # Single-leaf Merkle root is just the domain-separated leaf hash
    expected = hashlib.sha3_256(b"\x00" + bytes.fromhex(leaf)).hexdigest()
    assert root == expected


def test_build_and_verify_even_count() -> None:
    leaves = [_leaf(i) for i in range(4)]
    root = compute_merkle_root(leaves)
    for i in range(4):
        proof = build_proof(leaves, i, root)
        assert verify_inclusion(proof)
        assert proof.root == root
        assert proof.tree_size == 4


def test_build_and_verify_odd_count() -> None:
    leaves = [_leaf(i) for i in range(5)]
    root = compute_merkle_root(leaves)
    for i in range(5):
        proof = build_proof(leaves, i, root)
        assert verify_inclusion(proof), f"failed at index {i}"
        assert proof.root == root


def test_tampered_sibling_fails() -> None:
    leaves = [_leaf(i) for i in range(4)]
    root = compute_merkle_root(leaves)
    proof = build_proof(leaves, 1, root)
    # Corrupt a sibling hash
    tampered_siblings = list(proof.siblings)
    tampered_siblings[0] = "0" * 64
    from pqc_reasoning_ledger import InclusionProof

    bad = InclusionProof(
        leaf_hash=proof.leaf_hash,
        index=proof.index,
        tree_size=proof.tree_size,
        root=proof.root,
        siblings=tampered_siblings,
        directions=list(proof.directions),
    )
    assert not verify_inclusion(bad)
