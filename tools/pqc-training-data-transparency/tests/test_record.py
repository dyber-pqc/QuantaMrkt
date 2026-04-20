"""Tests for DataRecord and RecordHash."""

from pqc_training_data import DataRecord


def test_leaf_hash_deterministic() -> None:
    r1 = DataRecord(content=b"hello", metadata={"a": 1, "b": 2})
    r2 = DataRecord(content=b"hello", metadata={"b": 2, "a": 1})
    assert r1.leaf_hash().hex == r2.leaf_hash().hex
    # Sanity: hex is 64 chars (SHA3-256)
    assert len(r1.leaf_hash().hex) == 64


def test_leaf_hash_changes_with_content() -> None:
    r1 = DataRecord(content=b"alpha", metadata={"k": 1})
    r2 = DataRecord(content=b"beta", metadata={"k": 1})
    assert r1.leaf_hash().hex != r2.leaf_hash().hex


def test_leaf_hash_changes_with_metadata() -> None:
    r1 = DataRecord(content=b"same-content", metadata={"tag": "x"})
    r2 = DataRecord(content=b"same-content", metadata={"tag": "y"})
    assert r1.leaf_hash().hex != r2.leaf_hash().hex


def test_to_dict_does_not_include_raw_content() -> None:
    record = DataRecord(
        content=b"super secret training text",
        metadata={"source": "private"},
    )
    d = record.to_dict()
    assert "content" not in d
    # Must not contain the raw bytes
    assert b"super secret" not in repr(d).encode()
    # But has the safe fields
    assert d["content_size"] == len(b"super secret training text")
    assert len(d["content_sha3_256"]) == 64
    assert d["leaf_hash"] == record.leaf_hash().hex
