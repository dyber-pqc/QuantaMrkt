"""Tests for the Merkle tree."""

import pytest

from pqc_training_data import DataRecord, MerkleTree
from pqc_training_data.errors import (
    EmptyTreeError,
    IndexOutOfRangeError,
)


def _tree_from_records(records: list[DataRecord]) -> MerkleTree:
    t = MerkleTree()
    t.add_many([r.leaf_hash() for r in records])
    return t


def test_empty_tree_root_raises() -> None:
    tree = MerkleTree()
    with pytest.raises(EmptyTreeError):
        tree.root()


def test_single_leaf_root(single_record: DataRecord) -> None:
    tree = _tree_from_records([single_record])
    root = tree.root()
    # With one leaf, root is just H(0x00 || leaf_hash)
    assert len(root) == 64


def test_root_deterministic_same_inputs(sample_records: list[DataRecord]) -> None:
    t1 = _tree_from_records(sample_records)
    t2 = _tree_from_records(sample_records)
    assert t1.root() == t2.root()


def test_root_changes_with_leaf_change(sample_records: list[DataRecord]) -> None:
    t1 = _tree_from_records(sample_records)
    modified = list(sample_records)
    modified[2] = DataRecord(content=b"CHANGED", metadata={"doc_id": 2})
    t2 = _tree_from_records(modified)
    assert t1.root() != t2.root()


def test_inclusion_proof_even_count(sample_records: list[DataRecord]) -> None:
    # 5 records is odd - let's use 4 here for a balanced tree
    records = sample_records[:4]
    tree = _tree_from_records(records)
    root = tree.root()
    for i in range(4):
        proof = tree.inclusion_proof(i)
        assert proof.root == root
        assert proof.tree_size == 4
        assert proof.leaf_hash == records[i].leaf_hash().hex
        assert MerkleTree.verify_inclusion(proof)


def test_inclusion_proof_odd_count(odd_records: list[DataRecord]) -> None:
    # 7 leaves - exercises odd-level promotion in multiple places
    tree = _tree_from_records(odd_records)
    root = tree.root()
    for i in range(len(odd_records)):
        proof = tree.inclusion_proof(i)
        assert proof.root == root
        assert proof.tree_size == 7
        assert MerkleTree.verify_inclusion(proof)


def test_verify_inclusion_success(sample_records: list[DataRecord]) -> None:
    tree = _tree_from_records(sample_records)
    proof = tree.inclusion_proof(2)
    assert MerkleTree.verify_inclusion(proof) is True


def test_verify_inclusion_wrong_leaf_fails(sample_records: list[DataRecord]) -> None:
    tree = _tree_from_records(sample_records)
    proof = tree.inclusion_proof(2)
    # Replace leaf_hash with something else
    wrong_leaf = "0" * 64
    bad_proof = type(proof)(
        leaf_hash=wrong_leaf,
        index=proof.index,
        tree_size=proof.tree_size,
        root=proof.root,
        siblings=list(proof.siblings),
        directions=list(proof.directions),
    )
    assert MerkleTree.verify_inclusion(bad_proof) is False


def test_verify_inclusion_tampered_sibling_fails(sample_records: list[DataRecord]) -> None:
    tree = _tree_from_records(sample_records)
    proof = tree.inclusion_proof(1)
    tampered_siblings = list(proof.siblings)
    # Flip one character of the first sibling (still valid hex)
    first = tampered_siblings[0]
    swap = "f" if first[0] != "f" else "0"
    tampered_siblings[0] = swap + first[1:]
    bad_proof = type(proof)(
        leaf_hash=proof.leaf_hash,
        index=proof.index,
        tree_size=proof.tree_size,
        root=proof.root,
        siblings=tampered_siblings,
        directions=list(proof.directions),
    )
    assert MerkleTree.verify_inclusion(bad_proof) is False


def test_index_out_of_range_raises(sample_records: list[DataRecord]) -> None:
    tree = _tree_from_records(sample_records)
    with pytest.raises(IndexOutOfRangeError):
        tree.inclusion_proof(99)
    with pytest.raises(IndexOutOfRangeError):
        tree.inclusion_proof(-1)
